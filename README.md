# mynote

Self-hosted, single-user notes hub: **notes, checklists, and a private self-chat** in one Go binary with zero third-party dependencies, no database, and no JavaScript.

Everything lives under one data directory — back up that directory and you have backed up everything.

## Features

- **Notes** — Markdown-ish text files with `title` / `pinned` frontmatter; pinned-first ordering, case-insensitive search
- **Checklists** — JSON files with stable item IDs (toggling never hits the wrong item)
- **Self-chat** — append-only JSONL log; latest 200 messages shown
- **Auth** — single account, PBKDF2-HMAC-SHA256 (600k iterations), signed HMAC session cookies, CSRF-protected forms, failed-login delay
- **Account settings** — change username/password (invalidates all old sessions)
- Frontend — a letterpress-inspired editorial interface (Fraunces / Newsreader / Spline Sans Mono, paper grain, ink-inversion hovers, crop-mark cards) with a persistent light/dark "night edition" theme toggle. No-JS-first: every feature works without JavaScript; fonts come from Google Fonts with graceful local fallbacks when offline

> **UI direction (updated):** the monochrome editorial color palette is right, but the interface should **not be minimal** — and now it isn't: the design is a "private press" letterpress aesthetic (masthead + double rules, folio-numbered navigation, numbered note index with dotted leaders, manuscript editor on ruled paper, job-ticket checklists with progress rules, a colophon settings page, and a newspaper-front-page login). External frontend libraries (fonts, icons, CSS/tooling, JS frameworks) are allowed; serving JavaScript is allowed; rewriting the frontend in another language and splitting frontend/backend into separate apps is allowed if it serves the design. The backend storage model and data directory layout stay as the contract.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `MYNOTE_DATA_DIR` | `./data` | persistent storage directory (Docker image sets `/data`) |
| `MYNOTE_ADDR` | `:8080` | listen address |
| `MYNOTE_USERNAME` / `MYNOTE_PASSWORD` | — | bootstrap the account **only** if `auth.json` does not exist |
| `MYNOTE_PASSWORD_FILE` | — | Docker-secret-friendly alternative to `MYNOTE_PASSWORD` (mutually exclusive with it) |
| `MYNOTE_COOKIE_SECURE` | `false` | set `true` behind HTTPS |
| `MYNOTE_TIMEZONE` | `UTC` | IANA timezone for displayed timestamps (tzdata embedded) |

Passwords must be at least 12 characters. After first startup the bootstrap variables can be removed.

## Storage layout

```
data/
├── auth.json        # account + password KDF params + session version
├── secret.key       # HMAC key for session cookies
├── notes/<id>.md    # one file per note
├── checklists/<id>.json
└── chat.jsonl       # append-only self-chat
```

## Run locally

```sh
MYNOTE_USERNAME=me MYNOTE_PASSWORD=supersecret123 go run .
```

## Run with Docker Compose

By default state is kept in the local **`volumn/`** folder of this repo:

```sh
cp .env.example .env       # set MYNOTE_USERNAME / MYNOTE_PASSWORD
docker compose up -d --build
```

To use a named Docker volume instead: `MYNOTE_DATA_PATH=mynote-data docker compose up -d`

The container runs as root by default so fresh volumes work on any host (the app itself has no privileges and is isolated). For a hardened setup, pin a non-root user in `compose.yaml` (`user: "65532:65532"`) and make the data directory writable by it, e.g. `sudo chown -R 65532:65532 ./volumn`.

## HTTPS

Run the app behind a reverse proxy (Caddy, nginx, Traefik) that terminates TLS, and set `MYNOTE_COOKIE_SECURE=true`.

## Backup & restore

- **Backup:** stop the container (`docker compose stop`), copy the entire data directory (`volumn/` or your `MYNOTE_DATA_PATH`), start it again.
- **Restore:** with the container stopped, replace the whole directory with your copy and start the app.

## Upgrading

Pull the new code, `docker compose up -d --build`. Storage formats are versioned and forward-compatible within v1.

## Development

```sh
go test ./...        # unit + integration tests
go test -race ./...  # concurrency checks
go vet ./...
```

## Scope

Single account, single process, served at the URL root, TLS terminated by a reverse proxy. No file uploads, no multi-user, no Markdown-to-HTML rendering (bodies render as escaped plain text). One process per data directory — replicas are unsupported.

**Relaxed for the frontend:** JavaScript, external libraries, and richer detail are now allowed. A separate frontend (SPA in another language/framework talking to a backend API) is acceptable. The invariants that remain: single account, the `data/` directory storage formats, and the backup story.
