package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- helpers ----------

func testStore(t *testing.T) *store {
	t.Helper()
	dir := t.TempDir()
	s := newStore(dir)
	if err := s.init(); err != nil {
		t.Fatal(err)
	}
	return s
}

func testAuth(t *testing.T, s *store) authData {
	t.Helper()
	saltB64, hashB64, err := hashPassword("supersecret-pass", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := authData{Username: "me", Salt: saltB64, Hash: hashB64, SessionVersion: 1}
	if err := s.saveAuth(a); err != nil {
		t.Fatal(err)
	}
	return a
}

func testApp(t *testing.T) (*app, *store) {
	t.Helper()
	s := testStore(t)
	testAuth(t, s)
	key, err := s.loadSecret()
	if err != nil {
		t.Fatal(err)
	}
	return &app{
		cfg:   config{dataDir: s.dir, cookieSecure: false, timezone: "UTC"},
		store: s,
		key:   key,
		loc:   time.UTC,
	}, s
}

// newTestServer starts an httptest server for a fully configured app.
func newTestServer(t *testing.T) (*httptest.Server, *store) {
	t.Helper()
	s := testStore(t)
	testAuth(t, s)
	key, err := s.loadSecret()
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: config{dataDir: s.dir}, store: s, key: key, loc: time.UTC}
	mux := http.NewServeMux()
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
	srv := httptest.NewServer(a.limitBody(mux))
	t.Cleanup(srv.Close)
	return srv, s
}

// loginClient returns a client with a valid session cookie.
func loginClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.PostForm(srv.URL+"/login", url.Values{
		"username": {"me"}, "password": {"supersecret-pass"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	return client
}

func get(t *testing.T, c *http.Client, path string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(path)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, b.String()
}

func postForm(t *testing.T, c *http.Client, path string, form url.Values) *http.Response {
	t.Helper()
	resp, err := c.PostForm(path, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// extracts the CSRF token from a page's first hidden csrf input
func csrfFrom(t *testing.T, html string) string {
	t.Helper()
	marker := `name="csrf" value="`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatal("no csrf token in page")
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, `"`)
	return rest[:j]
}

// ---------- password hashing ----------

func TestPasswordHashRoundTrip(t *testing.T) {
	saltB64, hashB64, err := hashPassword("hunter2hunter2", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := base64.StdEncoding.DecodeString(saltB64)
	if len(salt) != saltLen {
		t.Fatalf("salt length = %d", len(salt))
	}
	hash, _ := base64.StdEncoding.DecodeString(hashB64)
	if len(hash) != keyLen {
		t.Fatalf("hash length = %d", len(hash))
	}
	a := authData{Salt: saltB64, Hash: hashB64, Iterations: iterations}
	if !verifyPassword("hunter2hunter2", a) {
		t.Error("correct password rejected")
	}
	if verifyPassword("wrong-password", a) {
		t.Error("wrong password accepted")
	}
	// random salts must differ between derivations
	_, hashB64b, _ := hashPassword("hunter2hunter2", nil, nil)
	if hashB64 == hashB64b {
		t.Error("same password produced identical hashes (salt not random)")
	}
}

// ---------- sessions ----------

func TestSessionSignAndParse(t *testing.T) {
	key := make([]byte, 32)
	hex.Decode(key, []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	a := authData{SessionVersion: 3}
	v, nonce, err := issueSession(key, a, time.Now())
	if err != nil || len(nonce) != 32 {
		t.Fatalf("issueSession: %v nonce=%q", err, nonce)
	}
	claims, ok := parseSession(key, v, time.Now(), 3)
	if !ok || claims.Nonce != nonce || claims.SessionVersion != 3 {
		t.Fatalf("valid session rejected: ok=%v claims=%+v", ok, claims)
	}
	// tampering invalidates
	if _, ok := parseSession(key, v+"x", time.Now(), 3); ok {
		t.Error("tampered value accepted")
	}
	// wrong key invalidates
	if _, ok := parseSession([]byte("other-key-32-bytes-long-xxxxxxxxxxxx"), v, time.Now(), 3); ok {
		t.Error("wrong key accepted")
	}
	// expiry invalidates
	v2, _, _ := issueSession(key, a, time.Now().Add(-2*sessionTTL))
	if _, ok := parseSession(key, v2, time.Now(), 3); ok {
		t.Error("expired session accepted")
	}
	// version bump invalidates
	if _, ok := parseSession(key, v, time.Now(), 4); ok {
		t.Error("obsolete session version accepted")
	}
	// garbage rejected
	for _, bad := range []string{"", "abc", "a.b", "...."} {
		if _, ok := parseSession(key, bad, time.Now(), 3); ok {
			t.Errorf("garbage %q accepted", bad)
		}
	}
}

func TestCSRFToken(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	tok := csrfToken(key, "nonce1")
	if !constantTimeEquals(tok, csrfToken(key, "nonce1")) {
		t.Error("same nonce must yield same token")
	}
	if constantTimeEquals(tok, csrfToken(key, "nonce2")) {
		t.Error("different nonce must yield different token")
	}
	if tok == csrfToken([]byte("other-key-also-32-chars."), "nonce1") {
		t.Error("different key must yield different token")
	}
}

// ---------- IDs ----------

func TestValidID(t *testing.T) {
	good := newID()
	if !validID(good) || len(good) != 32 {
		t.Fatalf("newID invalid: %q", good)
	}
	for _, bad := range []string{"", "../etc/passwd", strings.ToUpper(good), good + "0", strings.Repeat("g", 32), "../../"} {
		if validID(bad) {
			t.Errorf("invalid id accepted: %q", bad)
		}
	}
	// traversal-shaped IDs are just invalid
	if validID("c0ffee/c0ffee") {
		t.Error("path traversal accepted")
	}
}

// ---------- notes ----------

func TestNoteFrontmatterRoundTrip(t *testing.T) {
	src := serializeNote(noteMeta{Title: "Ideas", Pinned: true}, "line1\nline2\n")
	meta, body, err := parseNote(src)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Title != "Ideas" || !meta.Pinned || body != "line1\nline2\n" {
		t.Fatalf("round trip mismatch: %+v %q", meta, body)
	}
	// no frontmatter → whole body
	meta, body, err = parseNote([]byte("just text"))
	if err != nil || meta.Title != "" || body != "just text" {
		t.Fatalf("plain text parse: %+v %q %v", meta, body, err)
	}
}

func TestNoteListPinnedOrderAndSearch(t *testing.T) {
	s := testStore(t)
	mk := func(title string, pinned bool, body string) {
		id := newID()
		if err := s.saveNote(id, note{Meta: noteMeta{Title: title, Pinned: pinned}, Body: body}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	mk("Old pinned", true, "zebra body")
	mk("Newest", false, "apple body")
	mk("Middle", false, "banana ZEBRA body")
	notes, err := s.listNotes("")
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 3 {
		t.Fatalf("want 3 notes, got %d", len(notes))
	}
	if notes[0].Meta.Title != "Old pinned" {
		t.Errorf("pinned note not first: %q", notes[0].Meta.Title)
	}
	if notes[1].Meta.Title != "Middle" || notes[2].Meta.Title != "Newest" {
		t.Errorf("mtime ordering wrong: %q, %q", notes[1].Meta.Title, notes[2].Meta.Title)
	}
	// case-insensitive search over title and body
	for _, q := range []string{"ZEBRA", "zebra", "Apple", "old PIN"} {
		res, err := s.listNotes(q)
		if err != nil || len(res) == 0 {
			t.Errorf("search %q: %d results, err=%v", q, len(res), err)
		}
	}
	if res, _ := s.listNotes("nomatch-xyz"); len(res) != 0 {
		t.Error("nonmatching search returned results")
	}
}

// ---------- checklists ----------

func TestChecklistStableIDs(t *testing.T) {
	s := testStore(t)
	c := checklist{ID: newID(), Title: "Groceries", Items: []checklistItem{}}
	if err := s.saveChecklist(c); err != nil {
		t.Fatal(err)
	}
	got, err := s.loadChecklist(c.ID)
	if err != nil || got.Title != "Groceries" {
		t.Fatalf("load: %+v %v", got, err)
	}
	if got.ID != c.ID {
		t.Fatalf("ID not restored: %q", got.ID)
	}
	// on-disk JSON must not embed the ID
	raw, _ := os.ReadFile(filepath.Join(s.checklistsDir(), c.ID+".json"))
	if strings.Contains(string(raw), "\"ID\"") {
		t.Errorf("ID serialized to disk: %s", raw)
	}
	got.Items = append(got.Items, checklistItem{ID: newID(), Text: "milk"})
	if err := s.saveChecklist(got); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.loadChecklist(c.ID)
	if len(got2.Items) != 1 || got2.Items[0].ID != got.Items[0].ID {
		t.Fatalf("item ID not stable: %+v", got2.Items)
	}
	// toggle and delete by stable ID
	got2.Items[0].Done = true
	s.saveChecklist(got2)
	got3, _ := s.loadChecklist(c.ID)
	if !got3.Items[0].Done {
		t.Error("toggle not persisted")
	}
	got3.Items = got3.Items[:0]
	s.saveChecklist(got3)
	got4, _ := s.loadChecklist(c.ID)
	if len(got4.Items) != 0 {
		t.Error("delete not persisted")
	}
}

// ---------- chat ----------

func TestChatAppendLoadOrder(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 5; i++ {
		if err := s.appendChat(chatMessage{Time: time.Now().UTC(), Body: fmt.Sprintf("msg %d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := s.loadChat(chatRenderN)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 5 || msgs[0].Body != "msg 0" || msgs[4].Body != "msg 4" {
		t.Fatalf("order wrong: %+v", msgs)
	}
	// limit to most recent N, chronological order
	msgs, err = s.loadChat(2)
	if err != nil || len(msgs) != 2 || msgs[0].Body != "msg 3" || msgs[1].Body != "msg 4" {
		t.Fatalf("limit wrong: %+v %v", msgs, err)
	}
}

func TestChatMalformedTail(t *testing.T) {
	s := testStore(t)
	s.appendChat(chatMessage{Time: time.Now().UTC(), Body: "good"})
	f, _ := os.OpenFile(s.chatPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"t":"2025-01-01T00:00:00Z","body":"trunc`) // interrupted append
	f.Close()
	msgs, err := s.loadChat(chatRenderN)
	if err != nil {
		t.Fatalf("malformed tail should be skipped: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Body != "good" {
		t.Fatalf("unexpected messages: %+v", msgs)
	}
	// corruption earlier in the file is an error
	os.WriteFile(s.chatPath(), []byte("not json\n{\"t\":\"2025-01-01T00:00:00Z\",\"body\":\"x\"}\n"), 0o600)
	if _, err := s.loadChat(chatRenderN); err == nil {
		t.Error("mid-file corruption not detected")
	}
}

// ---------- atomic writes & concurrency ----------

func TestAtomicWriteNoTempLeftovers(t *testing.T) {
	s := testStore(t)
	s.atomicWrite(filepath.Join(s.dir, "f.txt"), []byte("x"), 0o600)
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestConcurrentMutations(t *testing.T) {
	s := testStore(t)
	testAuth(t, s)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				id := newID()
				s.mu.Lock()
				s.saveNote(id, note{Meta: noteMeta{Title: "t"}})
				s.mu.Unlock()
				s.appendChat(chatMessage{Time: time.Now().UTC(), Body: "x"})
				c := checklist{ID: newID(), Title: "c", Items: []checklistItem{}}
				s.mu.Lock()
				s.saveChecklist(c)
				s.mu.Unlock()
			}
		}()
	}
	wg.Wait()
	notes, _ := s.listNotes("")
	if len(notes) != 160 {
		t.Fatalf("notes lost under concurrency: %d", len(notes))
	}
	msgs, err := s.loadChat(chatRenderN)
	if err != nil || len(msgs) != 160 {
		t.Fatalf("chat corrupted: %d %v", len(msgs), err)
	}
}

// ---------- HTTP integration ----------

func TestProtectedRoutesRedirect(t *testing.T) {
	srv, _ := newTestServer(t)
	nofollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, path := range []string{"/", "/notes", "/checklists", "/chat", "/settings"} {
		resp, err := nofollow.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET %s unauthenticated = %d, want 303", path, resp.StatusCode)
		}
	}
}

func TestLoginFlow(t *testing.T) {
	srv, _ := newTestServer(t)
	// failure returns 401
	resp := postForm(t, http.DefaultClient, srv.URL+"/login", url.Values{"username": {"me"}, "password": {"wrong"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad login = %d, want 401", resp.StatusCode)
	}
	// success sets cookie
	c := loginClient(t, srv)
	resp, _ = get(t, c, srv.URL+"/notes")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authenticated /notes = %d", resp.StatusCode)
	}
	// root redirects to /notes
	resp, _ = get(t, c, srv.URL+"/")
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/notes" {
		t.Errorf("root = %d %s", resp.StatusCode, loc)
	}
}

func TestNoteWorkflowPersists(t *testing.T) {
	srv, s := newTestServer(t)
	c := loginClient(t, srv)
	_, page := get(t, c, srv.URL+"/notes")
	csrf := csrfFrom(t, page)
	resp := postForm(t, c, srv.URL+"/notes/new", url.Values{"title": {"My Note"}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create = %d", resp.StatusCode)
	}
	id := strings.TrimPrefix(resp.Header.Get("Location"), "/notes/")
	if !validID(id) {
		t.Fatalf("bad note id %q", id)
	}
	// save body
	resp = postForm(t, c, srv.URL+"/notes/"+id+"/save", url.Values{"title": {"My Note"}, "body": {"hello world"}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	if n, err := s.loadNote(id); err != nil || n.Body != "hello world" {
		t.Fatalf("persisted note: %+v %v", n, err)
	}
	// visible in list and searchable
	_, html := get(t, c, srv.URL+"/notes?q=hello")
	if !strings.Contains(html, "My Note") {
		t.Error("search did not surface the note")
	}
	// delete
	postForm(t, c, srv.URL+"/notes/"+id+"/delete", url.Values{"csrf": {csrf}})
	if _, err := s.loadNote(id); !os.IsNotExist(err) {
		t.Errorf("note still present after delete: %v", err)
	}
}

func TestChecklistWorkflow(t *testing.T) {
	srv, s := newTestServer(t)
	c := loginClient(t, srv)
	_, page := get(t, c, srv.URL+"/checklists")
	csrf := csrfFrom(t, page)
	resp := postForm(t, c, srv.URL+"/checklists/new", url.Values{"title": {"Errands"}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create = %d", resp.StatusCode)
	}
	// find the checklist ID from the returned page
	_, html := get(t, c, srv.URL+"/checklists")
	var listID string
	for _, id := range extractIDs(html, "/checklists/") {
		listID = id
		break
	}
	if listID == "" {
		t.Fatal("checklist id not found in page")
	}
	// add two items
	postForm(t, c, srv.URL+"/checklists/"+listID+"/add", url.Values{"text": {"milk"}, "csrf": {csrf}})
	postForm(t, c, srv.URL+"/checklists/"+listID+"/add", url.Values{"text": {"eggs"}, "csrf": {csrf}})
	cl, err := s.loadChecklist(listID)
	if err != nil || len(cl.Items) != 2 {
		t.Fatalf("items: %+v %v", cl, err)
	}
	// toggle the second item (stable IDs: first must stay untouched)
	second := cl.Items[1]
	resp = postForm(t, c, srv.URL+"/checklists/"+listID+"/toggle/"+second.ID, url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("toggle = %d", resp.StatusCode)
	}
	cl, _ = s.loadChecklist(listID)
	if !cl.Items[1].Done || cl.Items[0].Done {
		t.Fatalf("toggle hit wrong item: %+v", cl.Items)
	}
	// delete item by ID
	postForm(t, c, srv.URL+"/checklists/"+listID+"/items/"+second.ID+"/delete", url.Values{"csrf": {csrf}})
	cl, _ = s.loadChecklist(listID)
	if len(cl.Items) != 1 || cl.Items[0].Text != "milk" {
		t.Fatalf("delete hit wrong item: %+v", cl.Items)
	}
	// delete the checklist
	postForm(t, c, srv.URL+"/checklists/"+listID+"/delete", url.Values{"csrf": {csrf}})
	if _, err := s.loadChecklist(listID); !os.IsNotExist(err) {
		t.Error("checklist still present after delete")
	}
}

// extractIDs pulls 32-hex-char path-segment IDs following a prefix out of HTML.
func extractIDs(html, prefix string) []string {
	var out []string
	for {
		i := strings.Index(html, prefix)
		if i < 0 {
			return out
		}
		rest := html[i+len(prefix):]
		if len(rest) >= 32 && validID(rest[:32]) {
			out = append(out, rest[:32])
			html = rest[32:]
			continue
		}
		html = rest
	}
}

func TestChatWorkflow(t *testing.T) {
	srv, s := newTestServer(t)
	c := loginClient(t, srv)
	_, page := get(t, c, srv.URL+"/chat")
	csrf := csrfFrom(t, page)
	resp := postForm(t, c, srv.URL+"/chat/send", url.Values{"body": {"remember the milk"}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("send = %d", resp.StatusCode)
	}
	msgs, _ := s.loadChat(chatRenderN)
	if len(msgs) != 1 || msgs[0].Body != "remember the milk" {
		t.Fatalf("chat: %+v", msgs)
	}
	_, html := get(t, c, srv.URL+"/chat")
	if !strings.Contains(html, "remember the milk") {
		t.Error("chat page missing message")
	}
}

func TestCSRFRequired(t *testing.T) {
	srv, _ := newTestServer(t)
	c := loginClient(t, srv)
	bad := []struct {
		path string
		form url.Values
	}{
		{"/notes/new", url.Values{"title": {"x"}}},
		{"/checklists/new", url.Values{"title": {"x"}}},
		{"/chat/send", url.Values{"body": {"x"}}},
		{"/logout", nil},
		{"/settings/account", url.Values{"current": {"supersecret-pass"}, "username": {"me"}}},
	}
	for _, tc := range bad {
		resp := postForm(t, c, srv.URL+tc.path, tc.form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST %s without csrf = %d, want 400", tc.path, resp.StatusCode)
		}
		resp = postForm(t, c, srv.URL+tc.path, merge(url.Values{"csrf": {"forged"}}, tc.form))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST %s with forged csrf = %d, want 400", tc.path, resp.StatusCode)
		}
	}
}

func merge(a, b url.Values) url.Values {
	out := url.Values{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func TestSettingsAccountUpdate(t *testing.T) {
	srv, s := newTestServer(t)
	c := loginClient(t, srv)
	_, page := get(t, c, srv.URL+"/settings")
	csrf := csrfFrom(t, page)
	oldCookie := currentCookie(t, c, srv.URL)

	// wrong current password → 400, nothing changed
	resp := postForm(t, c, srv.URL+"/settings/account", url.Values{
		"current": {"wrong"}, "username": {"newname"}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong current password = %d", resp.StatusCode)
	}
	// correct update of username only
	resp = postForm(t, c, srv.URL+"/settings/account", url.Values{
		"current": {"supersecret-pass"}, "username": {"newname"}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("username update = %d", resp.StatusCode)
	}
	auth, _ := s.loadAuth()
	if auth.Username != "newname" {
		t.Errorf("username = %q", auth.Username)
	}
	if auth.SessionVersion != 2 {
		t.Errorf("session version = %d, want 2", auth.SessionVersion)
	}
	// a fresh cookie was issued (old one invalidated)
	if currentCookie(t, c, srv.URL) == oldCookie {
		t.Error("session cookie not rotated after account update")
	}
	// old-username login fails
	resp = postForm(t, http.DefaultClient, srv.URL+"/login", url.Values{"username": {"me"}, "password": {"supersecret-pass"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old username login = %d", resp.StatusCode)
	}
	// password change
	resp = postForm(t, c, srv.URL+"/settings/account", url.Values{
		"current": {"supersecret-pass"}, "username": {"newname"},
		"new_password": {"brand-new-password"}, "csrf": {csrfFrom(t, mustPage(t, c, srv.URL+"/settings"))}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("password update = %d", resp.StatusCode)
	}
	auth, _ = s.loadAuth()
	if !verifyPassword("brand-new-password", auth) {
		t.Error("new password does not verify")
	}
	if verifyPassword("supersecret-pass", auth) {
		t.Error("old password still verifies")
	}
	// short password rejected
	resp = postForm(t, c, srv.URL+"/settings/account", url.Values{
		"current": {"brand-new-password"}, "username": {"newname"},
		"new_password": {"short"}, "csrf": {csrfFrom(t, mustPage(t, c, srv.URL+"/settings"))}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("short password = %d", resp.StatusCode)
	}
}

func mustPage(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, body := get(t, c, url)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d", url, resp.StatusCode)
	}
	return body
}

func currentCookie(t *testing.T, c *http.Client, baseURL string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			return ck.Value
		}
	}
	return ""
}

func TestInputLimits(t *testing.T) {
	srv, s := newTestServer(t)
	c := loginClient(t, srv)
	_, page := get(t, c, srv.URL+"/notes")
	csrf := csrfFrom(t, page)
	// oversized title
	resp := postForm(t, c, srv.URL+"/notes/new", url.Values{"title": {strings.Repeat("x", 201)}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("long title = %d", resp.StatusCode)
	}
	// valid create then oversized body
	resp = postForm(t, c, srv.URL+"/notes/new", url.Values{"title": {"ok"}, "csrf": {csrf}})
	id := strings.TrimPrefix(resp.Header.Get("Location"), "/notes/")
	resp = postForm(t, c, srv.URL+"/notes/"+id+"/save", url.Values{
		"title": {"ok"}, "body": {strings.Repeat("x", maxNoteBody+1)}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("long body = %d", resp.StatusCode)
	}
	// body was not corrupted
	if n, err := s.loadNote(id); err != nil || n.Body != "" {
		t.Errorf("oversized save corrupted note: %q %v", n.Body, err)
	}
	// long checklist item
	resp = postForm(t, c, srv.URL+"/checklists/new", url.Values{"title": {"L"}, "csrf": {csrf}})
	_, html := get(t, c, srv.URL+"/checklists")
	listID := extractIDs(html, "/checklists/")[0]
	resp = postForm(t, c, srv.URL+"/checklists/"+listID+"/add", url.Values{"text": {strings.Repeat("x", 501)}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("long item = %d", resp.StatusCode)
	}
	// empty chat message
	resp = postForm(t, c, srv.URL+"/chat/send", url.Values{"body": {"   "}, "csrf": {csrf}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty chat = %d", resp.StatusCode)
	}
}

func TestNotFoundAndBadIDs(t *testing.T) {
	srv, _ := newTestServer(t)
	c := loginClient(t, srv)
	resp, _ := get(t, c, srv.URL+"/notes/00000000000000000000000000000000")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing note = %d", resp.StatusCode)
	}
	resp, _ = get(t, c, srv.URL+"/notes/not-a-valid-id")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("malformed id = %d", resp.StatusCode)
	}
	resp, _ = get(t, c, srv.URL+"/nosuchpage")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown route = %d", resp.StatusCode)
	}
	// traversal-shaped path values must 404, never touch the FS
	resp, _ = get(t, c, srv.URL+"/notes/..%2f..%2fauth.json")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("traversal = %d", resp.StatusCode)
	}
}

func TestHTMLEscaping(t *testing.T) {
	srv, _ := newTestServer(t)
	c := loginClient(t, srv)
	_, page := get(t, c, srv.URL+"/notes")
	csrf := csrfFrom(t, page)
	evil := `<script>alert(1)</script>`
	postForm(t, c, srv.URL+"/notes/new", url.Values{"title": {evil}, "csrf": {csrf}})
	_, html := get(t, c, srv.URL+"/notes")
	if strings.Contains(html, "<script>") {
		t.Error("unescaped HTML in note title")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected escaped title")
	}
	postForm(t, c, srv.URL+"/chat/send", url.Values{"body": {evil}, "csrf": {csrf}})
	_, html = get(t, c, srv.URL+"/chat")
	if strings.Contains(html, "<script>") {
		t.Error("unescaped HTML in chat")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	srv, _ := newTestServer(t)
	nofollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp := postForm(t, nofollow, srv.URL+"/login", url.Values{"username": {"me"}, "password": {"supersecret-pass"}})
	var found *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			found = ck
		}
	}
	if found == nil {
		t.Fatal("no session cookie set")
	}
	if !found.HttpOnly {
		t.Error("cookie not HttpOnly")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Error("cookie not SameSite=Lax")
	}
	if found.Path != "/" {
		t.Error("cookie path not /")
	}
	if found.MaxAge != int(sessionTTL.Seconds()) {
		t.Errorf("cookie MaxAge = %d", found.MaxAge)
	}
	if found.Secure {
		t.Error("Secure should be false without MYNOTE_COOKIE_SECURE")
	}
}

func TestLogoutInvalidatesAndClears(t *testing.T) {
	srv, _ := newTestServer(t)
	c := loginClient(t, srv)
	_, page := get(t, c, srv.URL+"/notes")
	csrf := csrfFrom(t, page)
	resp := postForm(t, c, srv.URL+"/logout", url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("logout = %d", resp.StatusCode)
	}
	// subsequent request is redirected to login
	resp, _ = get(t, c, srv.URL+"/notes")
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("after logout /notes = %d", resp.StatusCode)
	}
	// logout without csrf is rejected
	c2 := loginClient(t, srv)
	resp = postForm(t, c2, srv.URL+"/logout", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("csrf-less logout = %d", resp.StatusCode)
	}
}

// ---------- bootstrap behavior (process-level) ----------

func TestLoadConfigPasswordInputsExclusive(t *testing.T) {
	t.Setenv("MYNOTE_PASSWORD", "x")
	t.Setenv("MYNOTE_PASSWORD_FILE", "/tmp/x")
	if _, err := loadConfig(); err == nil {
		t.Error("both password inputs accepted")
	}
}

func TestAuthJSONFormat(t *testing.T) {
	s := testStore(t)
	a := testAuth(t, s)
	raw, err := os.ReadFile(s.authPath())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "username", "salt", "hash", "iterations", "session_version"} {
		if _, ok := m[k]; !ok {
			t.Errorf("auth.json missing key %q", k)
		}
	}
	if m["iterations"].(float64) != iterations {
		t.Errorf("iterations = %v", m["iterations"])
	}
	_ = a
}

func TestPermissions(t *testing.T) {
	s := testStore(t)
	testAuth(t, s)
	s.atomicWrite(s.secretPath(), []byte("00"), 0o600)
	fi, err := os.Stat(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("data dir mode = %o", fi.Mode().Perm())
	}
	fi, _ = os.Stat(s.authPath())
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("auth.json mode = %o", fi.Mode().Perm())
	}
	notes, _ := s.listNotes("")
	if len(notes) != 0 {
		t.Fatal("expected empty store")
	}
	s.saveNote(newID(), note{Meta: noteMeta{Title: "p"}})
	entries, _ := os.ReadDir(s.notesDir())
	fi, _ = entries[0].Info()
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("note file mode = %o", fi.Mode().Perm())
	}
}
