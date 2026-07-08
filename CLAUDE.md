# CLAUDE.md

Guidance for working in this repository.

## Project

WireGuard UI — a web UI for managing WireGuard VPN server + client configs.
Go backend (Echo v4) rendering server-side HTML templates + a jQuery/AdminLTE
frontend. This is a maintained fork of `ngoduykhanh/wireguard-ui` (upstream is
abandoned); the module path is still `github.com/ngoduykhanh/wireguard-ui`.
Fork-specific additions include GeoLite2 geolocation, Wake-on-LAN, Telegram
config delivery, and assorted settings.

## Build / test / run

There is no vendored toolchain; you need Go 1.21.

```bash
go build ./...        # compile
go vet ./...          # vet
go test ./...         # tests (currently geoip/ and util/)
gofmt -l .            # must print nothing (lint uses gofmt + goimports)
```

CI (`.github/workflows/`) runs golangci-lint (`gofmt, revive, goimports, govet,
unused, whitespace, misspell`) and a Docker build. Keep `gofmt -l .` clean.

Frontend assets (AdminLTE + plugins) are pulled from npm and assembled into
`assets/` by `./prepare_assets.sh` (or the Dockerfile) before the Go binary
embeds `templates/` and `assets/` via `//go:embed`. `custom/` (logo, favicon,
`js/helper.js`) is copied into `assets/custom/`. Running locally without
`prepare_assets.sh` yields a UI with no styling/JS; the Docker image is the
normal way to run it. `init.sh` is the container entrypoint and optionally
manages `wg-quick` up/down (`WGUI_MANAGE_START` / `WGUI_MANAGE_RESTART`).

## Layout

- `main.go` — flags/env parsing, DB init, route registration, server startup.
- `handler/` — Echo HTTP handlers (`routes.go` is the bulk; `session.go`,
  `middlewares.go`, `routes_wake_on_lan.go`).
- `router/` — Echo setup, template registry, request validator.
- `store/` + `store/jsondb/` — `IStore` interface over a flat-file JSON DB
  (`sdomino/scribble`); each client/user/setting is a JSON file under `./db/`.
- `model/` — data structs (`Client`, `User`, `Server`, `GlobalSetting`, ...).
- `util/` — config/env constants, WireGuard config generation, IP allocation,
  hashing, session helpers, in-memory caches.
- `emailer/` (SMTP + SendGrid), `telegram/`, `geoip/` (GeoLite2).
- `templates/` — server-rendered pages; `custom/js/helper.js` renders the
  client/user lists on the frontend.

## Conventions & gotchas

- **Templates use `text/template`, not `html/template`** (see `router/router.go`)
  — output is NOT auto-escaped. This is deliberate (e.g. the status page injects
  `</br>` into the Allocated IPs cell). Any user-controlled value rendered into
  a page must be escaped explicitly: server-side with `html.EscapeString` (see
  `Status` handler) or, in `helper.js`, with the `escapeHtml()` helper.
- **CSRF**: every non-GET route must include the `handler.ContentTypeJson`
  middleware. Browsers can't set `Content-Type: application/json` on cross-origin
  form posts, so this blocks CSRF. The frontend always sends JSON.
- **Auth**: cookie-session based (`gorilla/sessions`), two roles — admin and
  "manager" (non-admin). Admin-only routes add `handler.NeedsAdmin`. When
  `DISABLE_LOGIN` is set, auth is bypassed and everyone is treated as admin.
  Session validity is tied to a per-user CRC32 (`util.DBUsersToCRC32`) so any
  user change logs out other sessions.
- **Config-driven**: almost everything is set via `WGUI_*` env vars or flags
  (defined in `main.go` + `util/config.go`). Persisted settings live in
  `db/server/global_settings.json`.
- **Generated `wg0.conf`** is written by `util.WriteWireGuardServerConfig` in
  place (do not switch to write-temp-then-rename: the container's inotify watch
  needs `IN_CLOSE_WRITE` on the real path). It holds private keys, so it is
  written with mode `0600` by default (configurable via global settings /
  `WGUI_CONFIG_FILE_MODE`).
- **JSON request bodies** decoded into `map[string]interface{}` must use
  comma-ok type assertions (`v, ok := data["x"].(string)`) and return 400 on
  failure — a bare assertion panics on malformed input.
- Handler input from `c.Bind` / manual decode should be validated with the
  `util.Validate*` helpers before use.

## Git

- Commit messages: short and to the point. Do NOT add a `Co-Authored-By` line.
- Make one commit per logical change/fix/feature.
- Do not set the committer name/email manually (it breaks commit signing).
