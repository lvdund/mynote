# Plan: Self-Hosted Single-User Notes Hub

## Summary

Build the app described in `what_i_want.md` as a small Go web application with server-rendered HTML, no JavaScript, no database, and no third-party Go dependencies. The deployable application is one static binary; all mutable state lives under one configurable data directory that can be mounted as a Docker volume.

V1 includes notes, checklists, self-chat, single-user authentication, account/password updates, Docker packaging, and backup/deployment documentation. Arbitrary file uploads are out of scope.

## Application structure

- Use Go 1.22+ and only the standard library.
- Keep application logic, HTML templates, and CSS in `main.go`; parse templates from string constants so the source remains self-contained.
- Add only supporting project files: `go.mod`, `main_test.go`, `Dockerfile`, `compose.yaml`, `.dockerignore`, and an expanded `README.md`.
- Use `net/http` method-aware routing and path parameters.
- Render all pages with `html/template`; use ordinary HTML forms and Post/Redirect/Get after successful mutations.
- Add responsive, accessible CSS inline with the templates. No JavaScript and no external assets/CDNs.

## Configuration and startup

Support these environment variables:

- `MYNOTE_DATA_DIR`: persistent storage directory; defaults to `./data`. The Docker image sets it to `/data`.
- `MYNOTE_ADDR`: listen address; defaults to `:8080`.
- `MYNOTE_USERNAME` and `MYNOTE_PASSWORD`: bootstrap the account only when `auth.json` does not yet exist.
- `MYNOTE_PASSWORD_FILE`: optional Docker-secret-friendly alternative to `MYNOTE_PASSWORD`; reject startup if both password inputs are provided.
- `MYNOTE_COOKIE_SECURE`: defaults to `false`; set to `true` when served through HTTPS.
- `MYNOTE_TIMEZONE`: IANA timezone for displayed timestamps; defaults to `UTC`. Embed Go timezone data so this works in the minimal image.

At startup:

1. Create the data directory and required subdirectories with owner-only permissions.
2. Generate `secret.key` with cryptographically secure randomness if absent.
3. If `auth.json` is absent, require bootstrap credentials, validate them, create the account, and log that bootstrap variables can be removed.
4. If authentication already exists, ignore bootstrap credentials and emit a warning rather than replacing the account.
5. Fail clearly on unreadable, unwritable, malformed, or partially configured storage.

The process will handle `SIGINT`/`SIGTERM` with graceful HTTP shutdown. Configure sensible header/read/write/idle timeouts and log requests and errors to stdout/stderr without logging credentials, cookies, note bodies, checklist text, or chat content.

## Persistent storage model

Everything required to restore the app lives under `MYNOTE_DATA_DIR`:

```text
data/
├── auth.json
├── secret.key
├── notes/
│   └── <random-id>.md
├── checklists/
│   └── <random-id>.json
└── chat.jsonl
```

- Generate opaque lowercase hexadecimal IDs from `crypto/rand`; never derive paths from titles.
- Validate every route ID before filesystem access and only process regular files with the expected extension.
- Protect storage operations with one process-wide mutex. Running multiple app replicas against the same directory is explicitly unsupported.
- Write notes, checklists, and authentication data atomically through a temporary file in the same directory, file sync, rename, and directory sync where supported.
- Append each chat message as one JSONL record while holding the mutex and sync it before reporting success.
- Use restrictive permissions (`0700` directories, `0600` private files).

### Authentication data

Use a versioned `auth.json` format containing username, password-KDF parameters, and a session version. Implement PBKDF2-HMAC-SHA256 using standard-library primitives with:

- 16-byte random salt
- 600,000 iterations
- 32-byte derived key
- Base64-encoded salt and hash

Compare password hashes in constant time. Require usernames of 1–64 trimmed characters and passwords of at least 12 bytes.

### Notes

Store one Markdown-like text file per note:

```text
---
title: Ideas
pinned: true
---
note body
```

- Titles are single-line text, limited to 200 characters.
- Bodies are limited to 512 KiB.
- Render note bodies as escaped plain text with preserved whitespace and line breaks; actual Markdown-to-HTML conversion is intentionally out of scope for the zero-dependency version.
- Sort pinned notes first, then by modification time descending.
- Support case-insensitive title/body search through a `q` query parameter.

### Checklists

Store each checklist as JSON with stable item IDs:

```json
{
  "title": "Groceries",
  "items": [
    {"id": "<random-id>", "text": "milk", "done": false}
  ]
}
```

Stable IDs avoid toggling or deleting the wrong item when list contents change. Limit checklist titles to 200 characters and item text to 500 characters.

### Chat

Store UTC timestamps and message bodies as append-only JSONL records. Limit messages to 10 KiB and render the latest 200 messages in chronological order. A malformed final record caused by an interrupted append may be skipped with a warning; malformed earlier records are treated as storage corruption and produce a safe error page.

## Authentication and request security

- `GET /login` renders the form; `POST /login` verifies credentials.
- Delay every failed login response so it takes at least one second.
- Issue a signed, tamper-evident `mynote_session` cookie containing issue/expiry times, a random session nonce, and the current account session version.
- Sign cookies with HMAC-SHA256 using `secret.key`; reject malformed, expired, incorrectly signed, or obsolete-version cookies.
- Cookie attributes: `HttpOnly`, `SameSite=Lax`, `Path=/`, 30-day expiry, and configurable `Secure`.
- Protect every authenticated POST with a hidden CSRF token derived from the session nonce and signing key; validate it in constant time.
- Make logout a POST action, clear the cookie, and redirect to login.
- Account settings require the current password. Updating username or password increments the session version and issues a fresh session, invalidating all older cookies.
- Apply request body limits before parsing forms and return generic browser-facing errors while logging diagnostic details server-side.

## Pages and routes

Public routes:

- `GET /healthz` — lightweight liveness response without exposing stored data.
- `GET /login`
- `POST /login`

Authenticated routes:

- `GET /` — redirect to `/notes`.
- `POST /logout`
- `GET /notes` — list, pinned ordering, and optional search.
- `POST /notes/new` — create and redirect to its editor.
- `GET /notes/{id}` — view/edit page.
- `POST /notes/{id}/save`
- `POST /notes/{id}/delete`
- `GET /checklists` — render all checklists and their items.
- `POST /checklists/new`
- `POST /checklists/{id}/add`
- `POST /checklists/{id}/toggle/{itemID}`
- `POST /checklists/{id}/items/{itemID}/delete`
- `POST /checklists/{id}/delete`
- `GET /chat`
- `POST /chat/send`
- `GET /settings`
- `POST /settings/account`

Unknown resources return 404, invalid form input returns 400 with an actionable page, unauthenticated browser requests redirect to `/login`, and unexpected storage failures return 500 without leaking filesystem paths or secrets.

## Docker and configurable volumes

- Use a multi-stage Docker build with `CGO_ENABLED=0` and a `scratch` runtime image containing only the app binary, certificates, and a writable `/data` seed directory.
- Run as a fixed non-root numeric UID/GID and expose port 8080.
- `compose.yaml` mounts `${MYNOTE_DATA_PATH:-mynote-data}:/data`, allowing either the default named volume or a user-selected host path such as `/srv/mynote:/data`.
- Allow `PUID`/`PGID` overrides in Compose for bind-mounted host directories, and document that the selected directory must be writable by that identity.
- Pass bootstrap/configuration values through an `.env` file or Docker secret; do not bake them into the image.
- Document first startup, reverse-proxy HTTPS setup, changing the storage location, account bootstrap, password changes, upgrades, and recovery.
- Document backups as stopping the app, copying the entire mounted data directory/volume, and restarting it. Restoration is replacing that complete directory while the app is stopped.

## Testing and verification

Use only `testing`, `httptest`, and temporary directories.

### Unit tests

- PBKDF2 derivation/verification, random salts, wrong-password rejection, and constant-format persistence.
- Session signing, tamper detection, expiry, session-version invalidation, cookie flags, and CSRF validation.
- ID validation and path-traversal rejection.
- Note frontmatter parsing/serialization, pinned sorting, and case-insensitive search.
- Checklist create/add/toggle/delete behavior using stable item IDs.
- Chat append/load order, 200-message limit, and malformed-tail handling.
- Atomic rewrite behavior and concurrent mutation coverage under `go test -race`.

### HTTP integration tests

- Empty-data startup creates credentials only from complete bootstrap configuration.
- Login success/failure, protected-route redirects, logout, and account/password update flows.
- Every state-changing route rejects missing or invalid CSRF tokens.
- Full note, checklist, and chat workflows persist across a server restart using the same temporary data directory.
- Oversized and malformed input receives the intended 400/413 response without corrupting existing data.
- Missing resources, malformed IDs, and simulated storage failures produce safe responses.
- HTML rendering escapes user-controlled content.

### Build/deployment checks

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- Build and run the Docker image, bootstrap an account, exercise each feature, restart the container, and verify all data remains in the mounted volume.
- Verify both the default named volume and a custom bind-mounted `MYNOTE_DATA_PATH`.
- Confirm the container runs as non-root and that deleting/recreating it does not delete mounted data.

## Assumptions and explicit scope

- V1 is for exactly one account and one running process.
- It is served at the URL root, not under a configurable path prefix.
- TLS is terminated by a reverse proxy; the app itself serves HTTP.
- Arbitrary file uploads, multi-user access, external APIs, JSON HTTP endpoints, JavaScript/HTMX, rich Markdown rendering, checklist reordering, chat editing/deletion, and cross-process file locking are out of scope.
- Existing data migration is unnecessary because the repository currently contains no implementation or production storage format.
