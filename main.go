// mynote — self-hosted single-user notes hub.
// One binary, stdlib only, all state under a configurable data directory.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // embedded timezone data for minimal images
)

// ---------- configuration ----------

type config struct {
	dataDir      string
	addr         string
	username     string
	password     string
	passwordFile string
	cookieSecure bool
	timezone     string
}

func loadConfig() (config, error) {
	c := config{
		dataDir:      getenv("MYNOTE_DATA_DIR", "./data"),
		addr:         getenv("MYNOTE_ADDR", ":8080"),
		username:     os.Getenv("MYNOTE_USERNAME"),
		password:     os.Getenv("MYNOTE_PASSWORD"),
		passwordFile: os.Getenv("MYNOTE_PASSWORD_FILE"),
		cookieSecure: getenv("MYNOTE_COOKIE_SECURE", "false") == "true",
		timezone:     getenv("MYNOTE_TIMEZONE", "UTC"),
	}
	if c.password != "" && c.passwordFile != "" {
		return c, errors.New("MYNOTE_PASSWORD and MYNOTE_PASSWORD_FILE are mutually exclusive")
	}
	if c.passwordFile != "" {
		b, err := os.ReadFile(c.passwordFile)
		if err != nil {
			return c, fmt.Errorf("reading MYNOTE_PASSWORD_FILE: %w", err)
		}
		c.password = strings.TrimRight(string(b), "\r\n")
	}
	return c, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------- storage model ----------

const (
	iterations    = 600000
	keyLen        = 32
	saltLen       = 16
	maxNoteBody   = 512 << 10 // 512 KiB
	maxNoteTitle  = 200
	maxListTitle  = 200
	maxItemText   = 500
	maxChatMsg    = 10 << 10 // 10 KiB
	chatRenderN   = 200
	sessionTTL    = 30 * 24 * time.Hour
	sessionCookie = "mynote_session"
)

type authData struct {
	Version        int    `json:"version"`
	Username       string `json:"username"`
	Salt           string `json:"salt"` // base64
	Hash           string `json:"hash"` // base64
	Iterations     int    `json:"iterations"`
	SessionVersion int    `json:"session_version"`
}

type noteMeta struct {
	Title  string
	Pinned bool
}

type note struct {
	ID      string
	Meta    noteMeta
	Body    string
	ModTime time.Time
}

type checklistItem struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	Done bool   `json:"done"`
}

type checklist struct {
	ID    string          `json:"-"`
	Title string          `json:"title"`
	Items []checklistItem `json:"items"`
}

type chatMessage struct {
	Time time.Time `json:"t"`
	Body string    `json:"body"`
}

type store struct {
	dir string
	mu  sync.Mutex
}

func newStore(dir string) *store { return &store{dir: dir} }

func (s *store) init() error {
	for _, d := range []string{s.dir, s.notesDir(), s.checklistsDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", filepath.Base(d), err)
		}
		// MkdirAll does not adjust existing directories; enforce owner-only perms.
		// A bind mount owned by a different UID cannot be chmod'ed from inside
		// the container; warn instead of failing so the mount can still be used.
		if err := os.Chmod(d, 0o700); err != nil {
			log.Printf("warning: could not set 0700 on %s: %v", d, err)
		}
	}
	return nil
}

func (s *store) notesDir() string      { return filepath.Join(s.dir, "notes") }
func (s *store) checklistsDir() string { return filepath.Join(s.dir, "checklists") }
func (s *store) authPath() string      { return filepath.Join(s.dir, "auth.json") }
func (s *store) secretPath() string    { return filepath.Join(s.dir, "secret.key") }
func (s *store) chatPath() string      { return filepath.Join(s.dir, "chat.jsonl") }

// newID returns an opaque 32-char lowercase hex ID.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failure: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// validID rejects anything that is not 32 lowercase hex chars.
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// atomicWrite writes data to path via temp file + fsync + rename + dir sync.
func (s *store) atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// ---------- secret key ----------

func (s *store) loadSecret() ([]byte, error) {
	b, err := os.ReadFile(s.secretPath())
	if err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(key) != 32 {
			return nil, errors.New("secret.key is malformed")
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	if err := s.atomicWrite(s.secretPath(), []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return raw, nil
}

// ---------- password hashing (PBKDF2-HMAC-SHA256) ----------

func hashPassword(password string, salt, derived []byte) (saltB64, hashB64 string, err error) {
	if salt == nil {
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return "", "", err
		}
	}
	if derived == nil {
		d, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
		if err != nil {
			return "", "", err
		}
		derived = d
	}
	return base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(derived), nil
}

func verifyPassword(password string, a authData) bool {
	salt, err := base64.StdEncoding.DecodeString(a.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(a.Hash)
	if err != nil || len(want) != keyLen {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, a.Iterations, keyLen)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---------- auth persistence ----------

func (s *store) loadAuth() (authData, error) {
	var a authData
	b, err := os.ReadFile(s.authPath())
	if err != nil {
		return a, err
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return a, fmt.Errorf("auth.json is malformed: %w", err)
	}
	if a.Version != 1 || a.Username == "" || a.Iterations != iterations {
		return a, errors.New("auth.json has an unsupported format")
	}
	return a, nil
}

func (s *store) saveAuth(a authData) error {
	a.Version = 1
	a.Iterations = iterations
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return s.atomicWrite(s.authPath(), append(b, '\n'), 0o600)
}

func validUsername(u string) bool {
	u = strings.TrimSpace(u)
	return len(u) >= 1 && len(u) <= 64
}

func validPassword(p string) bool { return len(p) >= 12 }

// ---------- sessions ----------

type sessionClaims struct {
	ExpiresAt      int64  `json:"exp"`
	IssuedAt       int64  `json:"iat"`
	Nonce          string `json:"n"`
	SessionVersion int    `json:"sv"`
}

func signPayload(key []byte, payload []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// issueSession builds the signed cookie value "b64(payload).sig".
func issueSession(key []byte, a authData, now time.Time) (value string, nonce string, err error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", err
	}
	nonce = hex.EncodeToString(nonceBytes)
	claims := sessionClaims{
		ExpiresAt:      now.Add(sessionTTL).Unix(),
		IssuedAt:       now.Unix(),
		Nonce:          nonce,
		SessionVersion: a.SessionVersion,
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + signPayload(key, []byte(payload)), nonce, nil
}

// parseSession validates signature, expiry and session version.
func parseSession(key []byte, value string, now time.Time, currentVersion int) (sessionClaims, bool) {
	var claims sessionClaims
	dot := strings.LastIndexByte(value, '.')
	if dot < 0 {
		return claims, false
	}
	payload, sig := value[:dot], value[dot+1:]
	expected := signPayload(key, []byte(payload))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return claims, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		return claims, false
	}
	if now.Unix() >= claims.ExpiresAt || claims.SessionVersion != currentVersion {
		return claims, false
	}
	return claims, true
}

// csrfToken derives a per-session CSRF token.
func csrfToken(key []byte, nonce string) string {
	return signPayload(key, []byte("csrf:"+nonce))
}

func constantTimeEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------- notes ----------

func parseNote(data []byte) (noteMeta, string, error) {
	var meta noteMeta
	text := string(data)
	const sep = "---\n"
	if !strings.HasPrefix(text, sep) {
		return meta, text, nil
	}
	rest := text[len(sep):]
	idx := strings.Index(rest, "\n---\n")
	front, body := rest[:idx], rest[idx+5:]
	for _, line := range strings.Split(front, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "title":
			meta.Title = v
		case "pinned":
			meta.Pinned = v == "true"
		}
	}
	return meta, body, nil
}

func serializeNote(meta noteMeta, body string) []byte {
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("title: " + strings.ReplaceAll(meta.Title, "\n", " ") + "\n")
	b.WriteString(fmt.Sprintf("pinned: %t\n", meta.Pinned))
	b.WriteString("---\n")
	b.WriteString(body)
	return []byte(b.String())
}

func (s *store) loadNote(id string) (note, error) {
	var n note
	if !validID(id) {
		return n, errBadID
	}
	path := filepath.Join(s.notesDir(), id+".md")
	fi, err := os.Stat(path)
	if err != nil {
		return n, err
	}
	if !fi.Mode().IsRegular() {
		return n, errors.New("not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return n, err
	}
	meta, body, err := parseNote(data)
	if err != nil {
		return n, err
	}
	return note{ID: id, Meta: meta, Body: body, ModTime: fi.ModTime()}, nil
}

func (s *store) saveNote(id string, n note) error {
	if !validID(id) {
		return errBadID
	}
	return s.atomicWrite(filepath.Join(s.notesDir(), id+".md"), serializeNote(n.Meta, n.Body), 0o600)
}

func (s *store) deleteNote(id string) error {
	if !validID(id) {
		return errBadID
	}
	return os.Remove(filepath.Join(s.notesDir(), id+".md"))
}

func (s *store) listNotes(q string) ([]note, error) {
	entries, err := os.ReadDir(s.notesDir())
	if err != nil {
		return nil, err
	}
	ql := strings.ToLower(q)
	var notes []note
	for _, e := range entries {
		id, _ := strings.CutSuffix(e.Name(), ".md")
		if !e.Type().IsRegular() || !validID(id) {
			continue
		}
		n, err := s.loadNote(id)
		if err != nil {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(n.Meta.Title), ql) &&
			!strings.Contains(strings.ToLower(n.Body), ql) {
			continue
		}
		notes = append(notes, n)
	}
	sort.Slice(notes, func(i, j int) bool {
		if notes[i].Meta.Pinned != notes[j].Meta.Pinned {
			return notes[i].Meta.Pinned
		}
		return notes[i].ModTime.After(notes[j].ModTime)
	})
	return notes, nil
}

// ---------- checklists ----------

func (s *store) loadChecklist(id string) (checklist, error) {
	var c checklist
	if !validID(id) {
		return c, errBadID
	}
	path := filepath.Join(s.checklistsDir(), id+".json")
	fi, err := os.Stat(path)
	if err != nil {
		return c, err
	}
	if !fi.Mode().IsRegular() {
		return c, errors.New("not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("checklist %s is malformed", id[:8])
	}
	c.ID = id
	return c, nil
}

func (s *store) saveChecklist(c checklist) error {
	id := c.ID
	if !validID(id) {
		return errBadID
	}
	c.ID = "" // ID is the filename, not part of the JSON
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return s.atomicWrite(filepath.Join(s.checklistsDir(), id+".json"), b, 0o600)
}

func (s *store) deleteChecklist(id string) error {
	if !validID(id) {
		return errBadID
	}
	return os.Remove(filepath.Join(s.checklistsDir(), id+".json"))
}

func (s *store) listChecklists() ([]checklist, error) {
	entries, err := os.ReadDir(s.checklistsDir())
	if err != nil {
		return nil, err
	}
	var out []checklist
	for _, e := range entries {
		id, _ := strings.CutSuffix(e.Name(), ".json")
		if !e.Type().IsRegular() || !validID(id) {
			continue
		}
		c, err := s.loadChecklist(id)
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out, nil
}

// ---------- chat ----------

func (s *store) appendChat(msg chatMessage) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.chatPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// loadChat returns up to n most recent messages in chronological order.
// A malformed final record (interrupted append) is skipped with a warning;
// malformed earlier records are corruption.
func (s *store) loadChat(n int) ([]chatMessage, error) {
	data, err := os.ReadFile(s.chatPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	var msgs []chatMessage
	for i, line := range lines {
		var m chatMessage
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			if i == len(lines)-1 {
				log.Printf("chat: skipping malformed final record (interrupted append?)")
				continue
			}
			return nil, errors.New("chat log is corrupted")
		}
		msgs = append(msgs, m)
	}
	if len(msgs) > n {
		msgs = msgs[len(msgs)-n:]
	}
	return msgs, nil
}

// ---------- templates ----------

//go:embed assets.css
var cssFS embed.FS

var pageTmpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · mynote</title>
<style>{{.CSS}}</style>
</head>
<body>
<header>
<nav>
<a href="/notes" class="brand"><span class="brand-mark"></span>mynote</a>
<a href="/notes">Notes</a>
<a href="/checklists">Checklists</a>
<a href="/chat">Chat</a>
<a href="/settings">Settings</a>
<form method="post" action="/logout" class="inline nav-logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit" class="linklike">Log out</button></form>
</nav>
</header>
<main>
{{template "content" .}}
</main>
</body>
</html>
`))

var loginTmpl = template.Must(template.New("page").Funcs(template.FuncMap{"safeCSS": func(s string) template.CSS { return template.CSS(s) }}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log in · mynote</title>
<style>{{.CSS}}</style>
</head>
<body class="centered">
<main class="login-shell">
<section class="login-art"><a class="brand" href="/login"><span class="brand-mark"></span>mynote</a><div><h2>Your thoughts, in one place.</h2><p>A quiet, private space for notes, lists, and the things you want to remember.</p></div><div class="orbit" aria-hidden="true"></div></section>
<section class="login-form">
<p class="eyebrow">Private workspace</p><h1>Welcome back.</h1><p class="lede">Sign in to continue to your notes.</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="/login">
<label>Username <input name="username" autofocus autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Log in</button>
</form>
</section>
</main>
</body>
</html>
`))

var tmplFuncs = template.FuncMap{}

var notesTmpl = mustSub(`{{define "content"}}
<header class="page-head"><div><p class="eyebrow">Your workspace</p><h1>Notes</h1></div><p class="lede">Ideas, plans, and passing thoughts—kept private and close at hand.</p></header>
<div class="toolbar">
<form method="post" action="/notes/new" class="row">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input name="title" placeholder="New note title" maxlength="200" required>
<button type="submit">Create</button>
</form>
<form method="get" action="/notes" class="row">
<input name="q" value="{{.Query}}" placeholder="Search notes…">
<button type="submit">Search</button>
{{if .Query}}<a href="/notes" class="clear-link">Clear</a>{{end}}
</form>
</div>
<div class="section-label"><h2>{{if .Query}}Search results{{else}}All notes{{end}}</h2><span>{{len .Notes}} entries</span></div>
{{if not .Notes}}<p class="empty">No notes{{if .Query}} matching “{{.Query}}”{{end}}.</p>{{end}}
<ul class="notes">
{{range .Notes}}
<li><a href="/notes/{{.ID}}">{{.Meta.Title}}{{if .Meta.Pinned}}<span class="pin">Pinned</span>{{end}}</a>
 <span class="muted">{{.ModTime.Format "2006-01-02 15:04"}}</span></li>
{{end}}
</ul>
{{end}}`)

var noteTmpl = mustSub(`{{define "content"}}
<header class="page-head"><div><p class="eyebrow">Note editor</p><h1>{{.Note.Meta.Title}}</h1></div><p class="lede">Write without distraction. Changes stay in your private workspace.</p></header>
<section class="editor"><form method="post" action="/notes/{{.Note.ID}}/save">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Title <input name="title" value="{{.Note.Meta.Title}}" maxlength="200" required></label>
<label class="check"><input type="checkbox" name="pinned" value="true" {{if .Note.Meta.Pinned}}checked{{end}}> Pinned</label>
<textarea name="body" rows="20">{{.Note.Body}}</textarea>
<button type="submit">Save</button>
</form>
<form method="post" action="/notes/{{.Note.ID}}/delete" class="danger">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Delete note</button>
</form>
</section>
{{end}}`)

var checklistsTmpl = mustSub(`{{define "content"}}
<header class="page-head"><div><p class="eyebrow">Stay on track</p><h1>Checklists</h1></div><p class="lede">Turn busy thoughts into small, satisfying steps.</p></header>
<div class="toolbar">
<form method="post" action="/checklists/new" class="row">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input name="title" placeholder="New checklist title" maxlength="200" required>
<button type="submit">Create</button>
</form>
</div>
{{if not .Lists}}<p class="empty">No checklists yet.</p>{{end}}
<div class="checklist-grid">
{{range $list := .Lists}}
<section class="card">
<h2>{{$list.Title}}</h2>
<form method="post" action="/checklists/{{$list.ID}}/add" class="row">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input name="text" placeholder="Add item…" maxlength="500" required>
<button type="submit">Add</button>
</form>
<ul class="items">
{{range .Items}}
<li class="{{if .Done}}done{{end}}">
<form method="post" action="/checklists/{{$list.ID}}/toggle/{{.ID}}" class="inline">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button type="submit" class="linklike" aria-label="Toggle">{{if .Done}}☑{{else}}☐{{end}}</button>
</form>
<span>{{.Text}}</span>
<form method="post" action="/checklists/{{$list.ID}}/items/{{.ID}}/delete" class="inline">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button type="submit" class="linklike del" aria-label="Delete item">✕</button>
</form>
</li>
{{end}}
</ul>
<form method="post" action="/checklists/{{$list.ID}}/delete" class="danger">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button type="submit">Delete checklist</button>
</form>
</section>
{{end}}
</div>
{{end}}`)

var chatTmpl = mustSub(`{{define "content"}}
<header class="page-head"><div><p class="eyebrow">A private thread</p><h1>Note to self</h1></div><p class="lede">Send yourself a quick thought now. Find it here whenever you need it.</p></header>
<div class="toolbar">
<form method="post" action="/chat/send" class="row">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input name="body" placeholder="Remember to…" maxlength="10240" required autofocus>
<button type="submit">Send</button>
</form>
</div>
{{if not .Messages}}<p class="empty">No messages yet.</p>{{end}}
<ul class="chat">
{{range .Messages}}
<li><time>{{.Time.Format "2006-01-02 15:04"}}</time><span>{{.Body}}</span></li>
{{end}}
</ul>
{{end}}`)

var settingsTmpl = mustSub(`{{define "content"}}
<header class="page-head"><div><p class="eyebrow">Your preferences</p><h1>Settings</h1></div><p class="lede">Keep your account details current and your workspace secure.</p></header>
<section class="card">
<h2>Account</h2>
<form method="post" action="/settings/account">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Current password <input name="current" type="password" autocomplete="current-password" required></label>
<label>Username <input name="username" value="{{.Username}}" maxlength="64" required></label>
<details><summary>Change password</summary>
<label>New password (min 12 chars) <input name="new_password" type="password" autocomplete="new-password" minlength="12"></label>
</details>
<button type="submit">Save account</button>
</form>
</section>
{{end}}`)

var errorTmpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error · mynote</title><style>{{.CSS}}</style></head>
<body class="centered"><main class="card">
<h1>{{.Code}}</h1><p>{{.Message}}</p>
<p><a href="/notes">Back home</a></p>
</main></body></html>
`))

func mustSub(content string) *template.Template {
	t := template.Must(pageTmpl.Clone())
	return template.Must(t.Parse(content))
}

// ---------- application ----------

type app struct {
	cfg   config
	store *store
	key   []byte
	loc   *time.Location
}

type ctxKey int

const (
	authCtxKey   ctxKey = 0
	claimsCtxKey ctxKey = 1
)

var errBadID = errors.New("invalid id")

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	loc, err := time.LoadLocation(cfg.timezone)
	if err != nil {
		log.Fatalf("invalid MYNOTE_TIMEZONE %q: %v", cfg.timezone, err)
	}
	st := newStore(cfg.dataDir)
	if err := st.init(); err != nil {
		log.Fatalf("cannot initialize data directory: %v", err)
	}
	key, err := st.loadSecret()
	if err != nil {
		log.Fatalf("cannot load secret key: %v", err)
	}
	a := &app{cfg: cfg, store: st, key: key, loc: loc}

	// Bootstrap or verify account.
	if _, err := st.loadAuth(); errors.Is(err, fs.ErrNotExist) {
		if cfg.username == "" || cfg.password == "" {
			log.Fatal("no account exists; set MYNOTE_USERNAME and MYNOTE_PASSWORD (or MYNOTE_PASSWORD_FILE) to bootstrap one")
		}
		if !validUsername(cfg.username) || !validPassword(cfg.password) {
			log.Fatal("bootstrap credentials invalid: username 1-64 chars, password at least 12 bytes")
		}
		saltB64, hashB64, err := hashPassword(cfg.password, nil, nil)
		if err != nil {
			log.Fatalf("hashing bootstrap password: %v", err)
		}
		if err := st.saveAuth(authData{
			Username: strings.TrimSpace(cfg.username), Salt: saltB64, Hash: hashB64, SessionVersion: 1,
		}); err != nil {
			log.Fatalf("writing auth.json: %v", err)
		}
		log.Printf("account %q created; bootstrap credentials can now be removed from the environment", strings.TrimSpace(cfg.username))
	} else if err != nil {
		log.Fatalf("cannot read authentication data: %v", err)
	} else if cfg.username != "" || cfg.password != "" {
		log.Printf("warning: bootstrap credentials provided but an account already exists; ignoring them")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /login", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.handleLoginPost)
	mux.HandleFunc("GET /{$}", a.requireAuth(a.handleRoot))
	mux.HandleFunc("POST /logout", a.requireAuth(a.handleLogout))
	mux.HandleFunc("GET /notes", a.requireAuth(a.handleNotes))
	mux.HandleFunc("POST /notes/new", a.requireAuth(a.handleNoteNew))
	mux.HandleFunc("GET /notes/{id}", a.requireAuth(a.handleNote))
	mux.HandleFunc("POST /notes/{id}/save", a.requireAuth(a.handleNoteSave))
	mux.HandleFunc("POST /notes/{id}/delete", a.requireAuth(a.handleNoteDelete))
	mux.HandleFunc("GET /checklists", a.requireAuth(a.handleChecklists))
	mux.HandleFunc("POST /checklists/new", a.requireAuth(a.handleChecklistNew))
	mux.HandleFunc("POST /checklists/{id}/add", a.requireAuth(a.handleChecklistAdd))
	mux.HandleFunc("POST /checklists/{id}/toggle/{itemID}", a.requireAuth(a.handleChecklistToggle))
	mux.HandleFunc("POST /checklists/{id}/items/{itemID}/delete", a.requireAuth(a.handleChecklistItemDelete))
	mux.HandleFunc("POST /checklists/{id}/delete", a.requireAuth(a.handleChecklistDelete))
	mux.HandleFunc("GET /chat", a.requireAuth(a.handleChat))
	mux.HandleFunc("POST /chat/send", a.requireAuth(a.handleChatSend))
	mux.HandleFunc("GET /settings", a.requireAuth(a.handleSettings))
	mux.HandleFunc("POST /settings/account", a.requireAuth(a.handleSettingsPost))

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           a.limitBody(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("mynote listening on %s (data: configured)", cfg.addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

// limitBody caps all request bodies at a generous bound.
func (a *app) limitBody(next http.Handler) http.Handler {
	const max = 2 << 20 // 2 MiB covers note bodies with form overhead
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) now() time.Time { return time.Now().In(a.loc) }

func (a *app) css() string {
	b, _ := fs.ReadFile(cssFS, "assets.css")
	return string(b)
}

// ---------- render helpers ----------

func (a *app) renderPage(w http.ResponseWriter, status int, t *template.Template, title string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = title
	data["CSS"] = a.css()
	w.WriteHeader(status)
	if err := t.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func (a *app) renderSub(w http.ResponseWriter, status int, t *template.Template, title string, data map[string]any) {
	a.renderPage(w, status, t, title, data)
}

func (a *app) renderError(w http.ResponseWriter, status int, msg string) {
	a.renderPage(w, status, errorTmpl, "Error", map[string]any{"Code": status, "Message": msg})
}

func (a *app) authFrom(r *http.Request) (authData, bool) {
	v, ok := r.Context().Value(authCtxKey).(authData)
	return v, ok
}

func (a *app) claimsFrom(r *http.Request) (sessionClaims, bool) {
	v, ok := r.Context().Value(claimsCtxKey).(sessionClaims)
	return v, ok
}

// currentCSRF derives the CSRF token for the requester's session.
func (a *app) currentCSRF(r *http.Request) string {
	claims, ok := a.claimsFrom(r)
	if !ok {
		return ""
	}
	return csrfToken(a.key, claims.Nonce)
}

// requireAuth validates the session cookie and stashes auth + claims in context.
func (a *app) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.store.mu.Lock()
		auth, err := a.store.loadAuth()
		a.store.mu.Unlock()
		if err != nil {
			log.Printf("loading auth: %v", err)
			a.renderError(w, 500, "Storage is temporarily unavailable.")
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		claims, ok := parseSession(a.key, c.Value, time.Now(), auth.SessionVersion)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), authCtxKey, auth)
		ctx = context.WithValue(ctx, claimsCtxKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// checkCSRF validates the csrf form field against the session nonce.
func (a *app) checkCSRF(r *http.Request, claims sessionClaims) bool {
	return constantTimeEquals(r.FormValue("csrf"), csrfToken(a.key, claims.Nonce))
}

func (a *app) setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.cfg.cookieSecure,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (a *app) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: a.cfg.cookieSecure, MaxAge: -1,
	})
}

// ---------- auth handlers ----------

func (a *app) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	a.renderPage(w, 200, loginTmpl, "Log in", map[string]any{"CSS": a.css(), "Error": ""})
}

func (a *app) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if err := r.ParseForm(); err != nil {
		a.renderError(w, 400, "Invalid login submission.")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	a.store.mu.Lock()
	auth, err := a.store.loadAuth()
	a.store.mu.Unlock()
	ok := err == nil && username == auth.Username && verifyPassword(password, auth)
	if !ok {
		// Anti-bruteforce: every failed login takes at least one second.
		if d := time.Since(start); d < time.Second {
			time.Sleep(time.Second - d)
		}
		a.renderPage(w, 401, loginTmpl, "Log in", map[string]any{"CSS": a.css(), "Error": "Invalid username or password."})
		return
	}
	value, _, err := issueSession(a.key, auth, time.Now())
	if err != nil {
		log.Printf("issuing session: %v", err)
		a.renderError(w, 500, "Could not start a session.")
		return
	}
	a.setSessionCookie(w, value)
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func (a *app) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid logout request.")
		return
	}
	a.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// validSessionCSRF validates the csrf form field against the session nonce.
func (a *app) validSessionCSRF(r *http.Request) bool {
	claims, ok := a.claimsFrom(r)
	if !ok {
		return false
	}
	return a.checkCSRF(r, claims)
}

// ---------- notes handlers ----------

func (a *app) handleNotes(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	notes, err := a.store.listNotes(q)
	if err != nil {
		log.Printf("listing notes: %v", err)
		a.renderError(w, 500, "Could not load notes.")
		return
	}
	if notes == nil {
		notes = []note{}
	}
	a.renderSub(w, 200, notesTmpl, "Notes", map[string]any{"Notes": notes, "Query": q, "CSRF": a.currentCSRF(r)})
}

func (a *app) handleNoteNew(w http.ResponseWriter, r *http.Request) {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return
	}
	title := strings.TrimSpace(r.PostFormValue("title"))
	if title == "" || len(title) > maxNoteTitle {
		a.renderError(w, 400, "Title must be 1-200 characters.")
		return
	}
	id := newID()
	a.store.mu.Lock()
	err := a.store.saveNote(id, note{Meta: noteMeta{Title: title}})
	a.store.mu.Unlock()
	if err != nil {
		log.Printf("creating note: %v", err)
		a.renderError(w, 500, "Could not create the note.")
		return
	}
	http.Redirect(w, r, "/notes/"+id, http.StatusSeeOther)
}

func (a *app) handleNote(w http.ResponseWriter, r *http.Request) {
	n, err := a.store.loadNote(r.PathValue("id"))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errBadID) {
		a.renderError(w, 404, "That note does not exist.")
		return
	}
	if err != nil {
		log.Printf("loading note: %v", err)
		a.renderError(w, 500, "Could not load the note.")
		return
	}
	a.renderSub(w, 200, noteTmpl, n.Meta.Title, map[string]any{"Note": n, "CSRF": a.currentCSRF(r)})
}

func (a *app) handleNoteSave(w http.ResponseWriter, r *http.Request) {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return
	}
	id := r.PathValue("id")
	title := strings.TrimSpace(r.PostFormValue("title"))
	if title == "" || len(title) > maxNoteTitle {
		a.renderError(w, 400, "Title must be 1-200 characters.")
		return
	}
	a.store.mu.Lock()
	n, err := a.store.loadNote(id)
	if err == nil {
		n.Meta.Title = title
		n.Meta.Pinned = r.PostFormValue("pinned") == "true"
		n.Body = r.PostFormValue("body")
		if len(n.Body) > maxNoteBody {
			err = errTooLarge
		} else {
			err = a.store.saveNote(id, n)
		}
	}
	a.store.mu.Unlock()
	if errors.Is(err, errTooLarge) {
		a.renderError(w, 400, "Note body is too large (max 512 KiB).")
		return
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errBadID) {
		a.renderError(w, 404, "That note does not exist.")
		return
	}
	if err != nil {
		log.Printf("saving note: %v", err)
		a.renderError(w, 500, "Could not save the note.")
		return
	}
	http.Redirect(w, r, "/notes/"+id, http.StatusSeeOther)
}

var errTooLarge = errors.New("input too large")

func (a *app) handleNoteDelete(w http.ResponseWriter, r *http.Request) {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return
	}
	id := r.PathValue("id")
	a.store.mu.Lock()
	err := a.store.deleteNote(id)
	a.store.mu.Unlock()
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errBadID) {
		log.Printf("deleting note: %v", err)
		a.renderError(w, 500, "Could not delete the note.")
		return
	}
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

// ---------- checklist handlers ----------

func (a *app) handleChecklists(w http.ResponseWriter, r *http.Request) {
	lists, err := a.store.listChecklists()
	if err != nil {
		log.Printf("listing checklists: %v", err)
		a.renderError(w, 500, "Could not load checklists.")
		return
	}
	if lists == nil {
		lists = []checklist{}
	}
	a.renderSub(w, 200, checklistsTmpl, "Checklists", map[string]any{"Lists": lists, "CSRF": a.currentCSRF(r)})
}

func (a *app) handleChecklistNew(w http.ResponseWriter, r *http.Request) {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return
	}
	title := strings.TrimSpace(r.PostFormValue("title"))
	if title == "" || len(title) > maxListTitle {
		a.renderError(w, 400, "Title must be 1-200 characters.")
		return
	}
	c := checklist{Title: title, Items: []checklistItem{}}
	id := newID()
	c.ID = id
	a.store.mu.Lock()
	err := a.store.saveChecklist(c)
	a.store.mu.Unlock()
	if err != nil {
		log.Printf("creating checklist: %v", err)
		a.renderError(w, 500, "Could not create the checklist.")
		return
	}
	http.Redirect(w, r, "/checklists", http.StatusSeeOther)
}

func (a *app) handleChecklistAdd(w http.ResponseWriter, r *http.Request) {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return
	}
	id := r.PathValue("id")
	text := strings.TrimSpace(r.PostFormValue("text"))
	if text == "" || len(text) > maxItemText {
		a.renderError(w, 400, "Item text must be 1-500 characters.")
		return
	}
	a.store.mu.Lock()
	c, err := a.store.loadChecklist(id)
	if err == nil {
		c.Items = append(c.Items, checklistItem{ID: newID(), Text: text})
		err = a.store.saveChecklist(c)
	}
	a.store.mu.Unlock()
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errBadID) {
		a.renderError(w, 404, "That checklist does not exist.")
		return
	}
	if err != nil {
		log.Printf("adding item: %v", err)
		a.renderError(w, 500, "Could not add the item.")
		return
	}
	http.Redirect(w, r, "/checklists", http.StatusSeeOther)
}

func (a *app) withChecklistItem(w http.ResponseWriter, r *http.Request, fn func(*checklist, *checklistItem)) bool {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return false
	}
	id, itemID := r.PathValue("id"), r.PathValue("itemID")
	if !validID(itemID) {
		a.renderError(w, 404, "That item does not exist.")
		return false
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	c, err := a.store.loadChecklist(id)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errBadID) {
		a.renderError(w, 404, "That checklist does not exist.")
		return false
	}
	if err != nil {
		log.Printf("loading checklist: %v", err)
		a.renderError(w, 500, "Could not load the checklist.")
		return false
	}
	for i := range c.Items {
		if c.Items[i].ID == itemID {
			fn(&c, &c.Items[i])
			if err := a.store.saveChecklist(c); err != nil {
				log.Printf("saving checklist: %v", err)
				a.renderError(w, 500, "Could not update the checklist.")
				return false
			}
			http.Redirect(w, r, "/checklists", http.StatusSeeOther)
			return true
		}
	}
	a.renderError(w, 404, "That item does not exist.")
	return false
}

func (a *app) handleChecklistToggle(w http.ResponseWriter, r *http.Request) {
	a.withChecklistItem(w, r, func(_ *checklist, item *checklistItem) { item.Done = !item.Done })
}

func (a *app) handleChecklistItemDelete(w http.ResponseWriter, r *http.Request) {
	a.withChecklistItem(w, r, func(c *checklist, _ *checklistItem) {
		itemID := r.PathValue("itemID")
		out := c.Items[:0]
		for _, it := range c.Items {
			if it.ID != itemID {
				out = append(out, it)
			}
		}
		c.Items = out
	})
}

func (a *app) handleChecklistDelete(w http.ResponseWriter, r *http.Request) {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return
	}
	a.store.mu.Lock()
	err := a.store.deleteChecklist(r.PathValue("id"))
	a.store.mu.Unlock()
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errBadID) {
		log.Printf("deleting checklist: %v", err)
		a.renderError(w, 500, "Could not delete the checklist.")
		return
	}
	http.Redirect(w, r, "/checklists", http.StatusSeeOther)
}

// ---------- chat handlers ----------

func (a *app) handleChat(w http.ResponseWriter, r *http.Request) {
	msgs, err := a.store.loadChat(chatRenderN)
	if err != nil {
		log.Printf("loading chat: %v", err)
		a.renderError(w, 500, "Could not load chat history.")
		return
	}
	if msgs == nil {
		msgs = []chatMessage{}
	}
	for i := range msgs {
		msgs[i].Time = msgs[i].Time.In(a.loc)
	}
	a.renderSub(w, 200, chatTmpl, "Chat", map[string]any{"Messages": msgs, "CSRF": a.currentCSRF(r)})
}

func (a *app) handleChatSend(w http.ResponseWriter, r *http.Request) {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return
	}
	body := strings.TrimRight(r.PostFormValue("body"), "\r\n")
	if strings.TrimSpace(body) == "" {
		a.renderError(w, 400, "Message cannot be empty.")
		return
	}
	if len(body) > maxChatMsg {
		a.renderError(w, 400, "Message is too long (max 10 KiB).")
		return
	}
	if err := a.store.appendChat(chatMessage{Time: time.Now().UTC(), Body: body}); err != nil {
		log.Printf("appending chat: %v", err)
		a.renderError(w, 500, "Could not save the message.")
		return
	}
	http.Redirect(w, r, "/chat", http.StatusSeeOther)
}

// ---------- settings handlers ----------

func (a *app) handleSettings(w http.ResponseWriter, r *http.Request) {
	auth, _ := a.authFrom(r)
	a.renderSub(w, 200, settingsTmpl, "Settings", map[string]any{"Username": auth.Username, "CSRF": a.currentCSRF(r)})
}

func (a *app) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	if !a.validSessionCSRF(r) {
		a.renderError(w, 400, "Invalid request token.")
		return
	}
	current := r.PostFormValue("current")
	newUsername := strings.TrimSpace(r.PostFormValue("username"))
	newPassword := r.PostFormValue("new_password")

	if !validUsername(newUsername) {
		a.renderError(w, 400, "Username must be 1-64 characters.")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	auth, err := a.store.loadAuth()
	if err != nil {
		log.Printf("loading auth for settings: %v", err)
		a.renderError(w, 500, "Could not load account data.")
		return
	}
	if !verifyPassword(current, auth) {
		a.renderError(w, 400, "Current password is incorrect.")
		return
	}
	if newPassword != "" && !validPassword(newPassword) {
		a.renderError(w, 400, "New password must be at least 12 characters.")
		return
	}
	auth.Username = newUsername
	if newPassword != "" {
		saltB64, hashB64, err := hashPassword(newPassword, nil, nil)
		if err != nil {
			log.Printf("hashing new password: %v", err)
			a.renderError(w, 500, "Could not update the password.")
			return
		}
		auth.Salt, auth.Hash = saltB64, hashB64
	}
	auth.SessionVersion++ // invalidates all existing sessions
	if err := a.store.saveAuth(auth); err != nil {
		log.Printf("saving auth: %v", err)
		a.renderError(w, 500, "Could not save account changes.")
		return
	}
	value, _, err := issueSession(a.key, auth, time.Now())
	if err != nil {
		log.Printf("re-issuing session: %v", err)
		a.clearSessionCookie(w)
		a.renderError(w, 500, "Account updated; please log in again.")
		return
	}
	a.setSessionCookie(w, value)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
