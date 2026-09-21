# Revised Plan: One Binary, Files Only

## UI direction (supersedes "minimal / no JS" styling rules)

The **color palette is settled** — warm off-white editorial monochrome with a restrained dark mode. But the interface should **not be minimal**:

- Go for **rich detail**: layered typography, texture, iconography, micro-interactions, generous but composed layouts
- **External libraries are allowed** (fonts, icon sets, CSS frameworks, JS libraries, build tooling)
- **Another language is allowed** — the frontend may be rewritten (e.g. TypeScript + a framework)
- **Separate FE/BE is allowed** — a standalone frontend app talking to a backend API is fine
- What must not change: single user, the `data/` storage formats, one-folder backup

The constraints below describe the original stdlib-only starting point; treat them as backend invariants, not frontend restrictions.

## Concept

Single `main.go` (Go, stdlib only) — routes, HTML templates, and logic in one file. Templates embedded with `go:embed`, so the whole app is **one binary + one `data/` folder**. No API, no JSON — plain HTML forms, POST → redirect. Works with zero JavaScript.

## Layout

```
hub/
├── main.go              ← everything lives here
└── data/                ← created at runtime, backup = copy this folder
    ├── auth.json        ← username + password hash
    ├── notes/
    │   └── ideas.md     ← one markdown file per note
    ├── checklists/
    │   └── groceries.json
    └── chat.jsonl       ← chat with yourself
```

## Storage formats (no DB)

**`auth.json`** — hash, not plaintext (bcrypt, one tiny dep; or stdlib SHA-256 + salt if you want zero deps):

```json
{ "username": "me", "password_hash": "$2a$10$..." }
```

- can edit/update password

**Note** — markdown with a small frontmatter header:

```
---
title: Ideas
pinned: true
---
note body here...
```

**Checklist**:

```json
{ "title": "Groceries", "items": [ {"text": "milk", "done": false} ] }
```

**Chat** — JSONL, append-only, perfect fit for a log:

```
{"t":"2025-01-15T10:02:00Z","body":"remember to call dad"}
```

Loading = read file, take last N lines. Hundreds of notes/messages = still instant.

## Auth flow

- `GET /login` → form → `POST /login` → compare against `auth.json` (constant-time compare)
- Success → signed cookie (HMAC with a `secret.key` in data/), `HttpOnly`, `SameSite=Lax`
- Middleware wraps everything except `/login` + static
- Wrong password → sleep 1 second (enough anti-bruteforce for 1 user)
- One-time setup: `hub -setuser me -setpass ...` writes `auth.json`

## Routes (all form-based)

```
GET/POST /login                        GET /logout
GET  /notes            POST /notes/new
GET  /notes/:id        POST /notes/:id/save     POST /notes/:id/delete
GET  /checklists       POST /checklists/new
POST /checklists/:id/add        POST /checklists/:id/toggle/:n
GET  /chat             POST /chat/send
```

PRG pattern (Post → Redirect → Get), so no JS needed. Add htmx later only if you miss the snappiness.

## Build order

1. **Skeleton + login** — mux, embedded templates, auth.json, cookie, middleware
2. **Notes** — list dir, create/edit/delete files (this sets the pattern for everything)
3. **Chat** — append to jsonl + render (smallest feature, do it for motivation)
4. **Checklists** — read JSON, toggle item, write back
5. **Polish** — pinned notes, search (`strings.Contains` over files — trivial now!), CSS

## Two practical notes

- Wrap file writes in one global mutex (~5 lines) — protects against double-submit corrupting a file
- Markdown rendering: start with plain text + line breaks; add `goldmark` (one dep) later if you want real markdown

**Estimated: ~700 lines total in one file.** Backup is `rsync data/`, deploy is one binary + systemd or a compose file.
