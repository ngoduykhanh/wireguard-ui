# wireguard-ui

A web user interface to manage your WireGuard setup (peers, server config, QR/download, email/Telegram delivery, and optional Android push).

<img width="1465" height="830" alt="586670714-378f20c6-95b8-4a50-9d6d-e54840dbee0f" src="https://github.com/user-attachments/assets/794f8fae-3487-40f7-94a1-a8b7e6863512" />

<img width="1470" height="827" alt="586669648-09e0d427-bf12-4ca9-a737-aac957ee0ffb" src="https://github.com/user-attachments/assets/7036a022-f8d3-42de-958c-67e61d8ef7c0" />

<img width="1460" height="810" alt="586669676-b8ba9f0a-9c50-4e81-9d6d-6a7451b4264a" src="https://github.com/user-attachments/assets/8a8d06c8-36da-4d10-bb07-2bb71e7c193a" />

<img width="1457" height="819" alt="586669663-2b29cc56-36f5-46fe-a703-bae38f8e252f" src="https://github.com/user-attachments/assets/720c81f0-64ac-43dc-9107-024ca85f2a65" />

<img width="1468" height="821" alt="586669659-60d37783-6ea2-4198-aac5-b6efb1e5f332" src="https://github.com/user-attachments/assets/5bcc9ca8-fe6b-44b4-b35c-00dae72f0d4b" />

## Contents

### Getting started

- [WireGuard UI v2](#wireguard-ui-v2) — what changed in this fork; language and build notes
- [Quick install (scripted setup)](#quick-install-scripted-setup) — interactive Linux install with `setup-linux-production.sh`
- [Run WireGuard UI](#run-wireguard-ui) — binary, Docker Compose, default credentials

### Using the panel

- [Features](#features) — dashboard, traffic, logs, users, Passkeys overview
- [HTTP API reference](#http-api-reference) — JSON routes for integrations and the Android app

### Configuration

- [Environment variables](#environment-variables) — full reference table
- [Firebase Cloud Messaging (FCM)](#firebase-cloud-messaging-fcm) — push notifications for Android
- [Session idle timeout](#session-idle-timeout-settings--session--security) — minutes-based idle logout
- [Passkeys (WebAuthn)](#passkeys-webauthn) — passwordless login, Android Credential Manager, reverse proxy
- [Server UI (optional OS integration)](#server-ui-optional-os-integration) — `wg-quick`, sysctl, log tail

### Deployment on Linux

- [systemd: install and enable the web service](#systemd-install-and-enable-the-web-service) — unit file, data directory, environment files
- [Auto restart WireGuard daemon](#auto-restart-wireguard-daemon) — optional `wg-quick` reload when `wg.conf` changes

### Development

- [Continuous integration (GitHub Actions)](#continuous-integration-github-actions)
- [Build](#build) — assets, Docker image, binary
- [License](#license)

## WireGuard UI v2

This repository ships **version 2** of the WireGuard UI: an updated shell-style layout, richer monitoring and administration pages, Passkeys (WebAuthn) support, bilingual UI (English / Spanish via `locale/en.json` and `locale/es.json`), and extended optional OS integration (sysctl, `wg-quick` / `wg syncconf`, log tail) while keeping the same core purpose as the upstream project—manage peers, generate configs, and distribute them by QR, file, email, or Telegram.

**Notes**

- **Building from source**: run `./prepare_assets.sh` before `go build` when templates or static assets change (see [Build](#build)).
- **Changing UI language**: set **Language** under **Global settings**, save, click **Apply config** in the toolbar, then **reload the page** so server-rendered templates and client-side `WG_T` strings refresh.

## Quick install (scripted setup)

For a **first install on systemd-based Linux** (Debian, Ubuntu, RHEL-family, etc.), use the interactive script at the repository root:

```bash
cd /path/to/wireguard-ui
chmod +x setup-linux-production.sh
sudo ./setup-linux-production.sh
```

The script can:

- Install the **`wireguard-ui` binary** to `/usr/local/bin/wireguard-ui` (compile from source, copy a bundled `wireguard-ui-linux-*` artifact, or copy your own build)
- Register and enable a **systemd** unit (`wireguard-ui.service`) for automatic start on boot
- Create paths under `/etc/wireguard-ui` and `/var/lib/wireguard-ui`
- Generate `SESSION_SECRET_FILE` and environment file
- Optionally copy a **Firebase service-account JSON** and set `FCM_CREDENTIALS_FILE`
- Optionally store **Android passkey** SHA-256 fingerprints and WebAuthn env vars
- Optionally install **Caddy** (Debian/Ubuntu) and append an `import` to `/etc/caddy/Caddyfile`

Review the prompts before exposing the panel on the internet. You will still need HTTPS for Passkeys in production—see [Passkeys (WebAuthn)](#passkeys-webauthn) and [systemd: install and enable the web service](#systemd-install-and-enable-the-web-service) for manual steps, reverse-proxy examples, and permission details the script does not fully automate.

---

## Features

### Classic capabilities (upstream parity)

- Web UI to manage WireGuard peers (create, edit, enable/disable, remove).
- Richer client records (name, email, notes, subnet ranges, Telegram user id, etc.).
- Distribute configs via **QR code**, **download**, **email**, or **Telegram**.
- Global defaults (endpoint, DNS, MTU, keepalive, config path) and server interface editor.
- Optional **Apply config** workflow to write `wg.conf` and optionally reload the kernel (`wg-quick` / `wg syncconf` when enabled).

### New in v2

- **Shell layout**: fixed sidebar + main content (`wgshell.css`), mobile-friendly nav, unified top bar with **Apply config** / pending-change handling.
- **Dashboard**: at-a-glance server/client KPIs, WireGuard presence, and actions that match live data (`/api/dashboard-stats`, restart helpers where configured).
- **Traffic**: bandwidth view backed by cached WireGuard counter samples (`/api/wg-traffic-series`), range presets, peer-aware charts.
- **Logs**: live sections when enabled (global "Logs" toggle)—optional file tail (`WGUI_LOG_TAIL_PATH`), `systemctl` / `journalctl` snippets for `wg-quick@...`, periodic refresh from `/api/system-logs`.
- **Status**: read-only peer table from `wgctrl` for quick inspection.
- **Global settings (expanded)**: configurable **session idle timeout** (minutes), **Passkeys** master toggle, **UI theme** (dark / light / auto), **UI language** (English / Spanish), **realtime stats** gate for Logs/Dashboard polling; staged save + apply flow with localStorage dirty tracking.
- **Internationalization**: strings in `locale/en.json` and `locale/es.json`; templates use `tr` / client bundle `WG_T` + `wgT()` for JS toasts and dynamic UI.
- **Multi-user auth**: **Users** admin page—create/edit/delete users, admin role, suspend account, revoke all sessions, inline Passkey add/remove/rename per user.
- **My account / Profile**: self-service display name, email, password change, own Passkeys.
- **Passkeys (WebAuthn)**: passwordless sign-in and registration; see [Passkeys (WebAuthn)](#passkeys-webauthn) for server env vars, Android Credential Manager, and reverse-proxy setup.
- **Server page extras** (Linux, when allowed): optional **IPv4 forwarding** via `sysctl`, **persist** / **auto-apply** preferences, `**wg-quick` down/up/restart** and `**wg syncconf`** after apply, optional **systemd**-based restarts.
- **Wake-on-LAN**: manage hosts and send magic packets from the UI.
- **Client list UX**: card layout with inline enable toggle, traffic chips fed by `/api/wg-peer-stats`, and "Apply config" integration after edits.

## HTTP API reference

Unless noted otherwise, paths are rooted at your configured `**BASE_PATH`** (empty at the site root, or e.g. `/wireguard`). Prefix every path below with that value.

**Sessions.** Most endpoints require a valid browser session cookie (`ValidSession`). A few JSON `POST` routes are public for Passkey login. JSON bodies expect `**Content-Type: application/json`** (this also mitigates simple CSRF from third-party sites).

**Admin-only** routes additionally require an administrator account (`NeedsAdmin` in the code).

### Well-known and health


| Method        | Path                           | Auth | Purpose                                                                                                                              |
| ------------- | ------------------------------ | ---- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `GET`, `HEAD` | `/.well-known/assetlinks.json` | No   | Digital Asset Links for Android Passkeys / Credential Manager (also mirrored under `BASE_PATH` when set; see comments in `main.go`). |
| `GET`         | `{BASE}/_health`               | No   | Liveness probe.                                                                                                                      |


### Public and login

When login is **not** disabled:


| Method | Path                                | Auth | Purpose                                        |
| ------ | ----------------------------------- | ---- | ---------------------------------------------- |
| `GET`  | `{BASE}/login`                      | No   | Login HTML.                                    |
| `POST` | `{BASE}/login`                      | No   | Password login (JSON).                         |
| `GET`  | `{BASE}/api/public/login-wg-status` | No   | WireGuard tunnel summary for the login banner. |
| `POST` | `{BASE}/api/passkeys/login/begin`   | No   | WebAuthn assertion options (JSON).             |
| `POST` | `{BASE}/api/passkeys/login/finish`  | No   | Complete Passkey login (JSON).                 |


### Passkeys (authenticated)

Browser and Android clients use these routes. Server setup: [Passkeys (WebAuthn)](#passkeys-webauthn).

| Method | Path                                            | Notes                              |
| ------ | ----------------------------------------------- | ---------------------------------- |
| `POST` | `{BASE}/api/passkeys/register/:username/begin`  | Start registration for `username`. |
| `POST` | `{BASE}/api/passkeys/register/:username/finish` | Finish registration.               |
| `POST` | `{BASE}/api/passkeys/remove`                    | Remove a credential.               |
| `POST` | `{BASE}/api/passkeys/rename`                    | Rename a credential.               |


### Users and profile


| Method | Path                              | Notes                          |
| ------ | --------------------------------- | ------------------------------ |
| `POST` | `{BASE}/update-user`              | Update profile fields.         |
| `POST` | `{BASE}/create-user`              | **Admin.** Create user.        |
| `POST` | `{BASE}/remove-user`              | **Admin.** Remove user.        |
| `GET`  | `{BASE}/get-users`                | **Admin.** List users.         |
| `GET`  | `{BASE}/api/user/:username`       | Fetch one user.                |
| `GET`  | `{BASE}/api/profile/passkeys`     | Passkeys for the current user. |
| `POST` | `{BASE}/api/user/set-admin`       | **Admin.**                     |
| `POST` | `{BASE}/api/user/set-disabled`    | **Admin.**                     |
| `POST` | `{BASE}/api/user/revoke-sessions` | **Admin.**                     |


### Peers (clients)


| Method | Path                          | Notes                        |
| ------ | ----------------------------- | ---------------------------- |
| `GET`  | `{BASE}/api/clients`          | List all clients.            |
| `GET`  | `{BASE}/api/client/:id`       | One client by numeric `id`.  |
| `POST` | `{BASE}/new-client`           | Create client.               |
| `POST` | `{BASE}/update-client`        | Update client.               |
| `POST` | `{BASE}/remove-client`        | Delete client.               |
| `POST` | `{BASE}/client/set-status`    | Enable/disable.              |
| `POST` | `{BASE}/email-client`         | Email configuration.         |
| `POST` | `{BASE}/send-telegram-client` | Telegram delivery.           |
| `GET`  | `{BASE}/download`             | Download one `.conf`.        |
| `GET`  | `{BASE}/download-all-configs` | **Admin.** ZIP of all peers. |


### Dashboard, stats, and traffic


| Method | Path                            | Notes                                                                                |
| ------ | ------------------------------- | ------------------------------------------------------------------------------------ |
| `GET`  | `{BASE}/api/dashboard-stats`    | KPIs for the dashboard.                                                              |
| `GET`  | `{BASE}/api/wg-peer-stats`      | Per-peer WireGuard counters (`rx`/`tx` from the kernel) plus `connected` (recent handshake, same rule as the dashboard). |
| `GET`  | `{BASE}/api/wg-traffic-series`  | Cached series; query `range=24h` (default), `7d`, or `30d`.                          |
| `GET`  | `{BASE}/api/machine-ips`        | Suggested endpoint IPs.                                                              |
| `GET`  | `{BASE}/api/subnet-ranges`      | Ordered subnet ranges.                                                               |
| `GET`  | `{BASE}/api/suggest-client-ips` | IP allocation hints.                                                                 |
| `GET`  | `{BASE}/api/ui-nav-hints`       | Small JSON payload; useful as a **connectivity / session check** for native clients. |


### WireGuard server, apply, and tunnel control


| Method | Path                                 | Notes                                        |
| ------ | ------------------------------------ | -------------------------------------------- |
| `POST` | `{BASE}/wg-server/interfaces`        | **Admin.** Save interface list from UI flow. |
| `POST` | `{BASE}/api/wg-server/save-page`     | **Admin.** Combined “Server” tab JSON save.  |
| `POST` | `{BASE}/wg-server/keypair`           | **Admin.** Generate server keypair.          |
| `POST` | `{BASE}/api/apply-wg-config`         | Write `wg.conf` / apply workflow (JSON).     |
| `GET`  | `{BASE}/api/wireguard/tunnel-status` | Tunnel up/down and interface summary.        |
| `POST` | `{BASE}/api/wireguard/wg-quick-down` | **Admin.** `wg-quick` down.                  |
| `POST` | `{BASE}/api/wireguard/wg-quick-up`   | **Admin.** `wg-quick` up.                    |


### Push notifications (FCM)


| Method | Path                         | Body (JSON)                                                 |
| ------ | ---------------------------- | ----------------------------------------------------------- |
| `POST` | `{BASE}/api/push/register`   | `{"token":"<FCM registration token>","platform":"android"}` |
| `POST` | `{BASE}/api/push/unregister` | `{"token":"<FCM registration token>"}`                      |


Requires a valid session. See [Firebase Cloud Messaging (FCM)](#firebase-cloud-messaging-fcm) for server env vars.

### Global settings and logs


| Method | Path                                        | Notes                                   |
| ------ | ------------------------------------------- | --------------------------------------- |
| `POST` | `{BASE}/global-settings`                    | **Admin.** Save global settings (JSON). |
| `POST` | `{BASE}/api/global-settings/realtime-stats` | **Admin.** Toggle realtime stats.       |
| `GET`  | `{BASE}/api/system-logs`                    | Log tail / snippets when enabled.       |


### Wake-on-LAN


| Method   | Path                                   |
| -------- | -------------------------------------- |
| `POST`   | `{BASE}/wake_on_lan_host`              |
| `DELETE` | `{BASE}/wake_on_lan_host/:mac_address` |
| `PUT`    | `{BASE}/wake_on_lan_host/:mac_address` |


### HTML pages (session)

These return HTML for the v2 shell, not JSON: `{BASE}/` (clients), `{BASE}/dashboard`, `{BASE}/traffic`, `{BASE}/logs`, `{BASE}/profile`, `{BASE}/users-settings` (**admin**), `{BASE}/wg-server` (**admin**), `{BASE}/global-settings` (**admin**), `{BASE}/status`, `{BASE}/wake_on_lan_hosts`, `{BASE}/about`. Use the JSON routes above for API integrations.

### Logout and misc


| Method | Path               | Notes                                 |
| ------ | ------------------ | ------------------------------------- |
| `GET`  | `{BASE}/logout`    | Ends session when login is enabled.   |
| `GET`  | `{BASE}/test-hash` | Internal/config hash probe (session). |
| `GET`  | `{BASE}/favicon`   | Favicon bytes.                        |


---

## Run WireGuard UI

> **Default credentials:** username and password are both `admin`. Change them after the first login.

For a guided Linux install (systemd unit, secrets paths, optional Caddy), start with [Quick install (scripted setup)](#quick-install-scripted-setup).

### Using binary file

Download the binary file from the release page and run it directly on the host machine

```
./wireguard-ui
```

For a **persistent** install on Linux, register **systemd** as described in **[systemd: install and enable the web service](#systemd-install-and-enable-the-web-service)** below (working directory, database, environment files, permissions).

### Using docker compose

The [examples/docker-compose](examples/docker-compose) folder contains example docker-compose files.
Choose the example which fits you the most, adjust the configuration for your needs, then run it like below:

```
docker-compose up
```

## Environment variables

Process environment and `EnvironmentFile=` entries for systemd/Docker. Grouped topics below: [FCM](#firebase-cloud-messaging-fcm), [session idle timeout](#session-idle-timeout-settings--session--security), [Passkeys](#passkeys-webauthn), [Server UI / WireGuard integration](#server-ui-optional-os-integration).

| Variable                         | Description                                                                                                                                                                                                                                                                                           | Default                            |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `BASE_PATH`                      | Set this variable if you run wireguard-ui under a subpath of your reverse proxy virtual host (e.g. /wireguard)                                                                                                                                                                                        | N/A                                |
| `BIND_ADDRESS`                   | The addresses that can access to the web interface and the port, use unix:///abspath/to/file.socket for unix domain socket.                                                                                                                                                                           | 0.0.0.0:80                         |
| `SESSION_SECRET`                 | The secret key used to encrypt the session cookies. Set this to a random value                                                                                                                                                                                                                        | N/A                                |
| `SESSION_SECRET_FILE`            | Optional filepath for the secret key used to encrypt the session cookies. Leave `SESSION_SECRET` blank to take effect                                                                                                                                                                                 | N/A                                |
| `SESSION_MAX_DURATION`           | Max time in days a remembered session is refreshed and valid. Non-refreshed session is valid for 7 days max, regardless of this setting.                                                                                                                                                              | 90                                 |
| `SUBNET_RANGES`                  | The list of address subdivision ranges. Format: `SR Name:10.0.1.0/24; SR2:10.0.2.0/24,10.0.3.0/24` Each CIDR must be inside one of the server interfaces.                                                                                                                                             | N/A                                |
| `WGUI_USERNAME`                  | The username for the login page. Used for db initialization only                                                                                                                                                                                                                                      | `admin`                            |
| `WGUI_PASSWORD`                  | The password for the user on the login page. Will be hashed automatically. Used for db initialization only                                                                                                                                                                                            | `admin`                            |
| `WGUI_PASSWORD_FILE`             | Optional filepath for the user login password. Will be hashed automatically. Used for db initialization only. Leave `WGUI_PASSWORD` blank to take effect                                                                                                                                              | N/A                                |
| `WGUI_PASSWORD_HASH`             | The password hash for the user on the login page. (alternative to `WGUI_PASSWORD`). Used for db initialization only                                                                                                                                                                                   | N/A                                |
| `WGUI_PASSWORD_HASH_FILE`        | Optional filepath for the user login password hash. (alternative to `WGUI_PASSWORD_FILE`). Used for db initialization only. Leave `WGUI_PASSWORD_HASH` blank to take effect                                                                                                                           | N/A                                |
| `WGUI_ENDPOINT_ADDRESS`          | The default endpoint address used in global settings where clients should connect to. The endpoint can contain a port as well, useful when you are listening internally on the `WGUI_SERVER_LISTEN_PORT` port, but you forward on another port (ex 9000). Ex: myvpn.dyndns.com:9000                   | Resolved to your public ip address |
| `WGUI_FAVICON_FILE_PATH`         | The file path used as website favicon                                                                                                                                                                                                                                                                 | Embedded WireGuard logo            |
| `WGUI_DNS`                       | The default DNS servers (comma-separated-list) used in the global settings                                                                                                                                                                                                                            | `1.1.1.1`                          |
| `WGUI_MTU`                       | The default MTU used in global settings                                                                                                                                                                                                                                                               | `1450`                             |
| `WGUI_PERSISTENT_KEEPALIVE`      | The default persistent keepalive for WireGuard in global settings                                                                                                                                                                                                                                     | `15`                               |
| `WGUI_FIREWALL_MARK`             | The default WireGuard firewall mark                                                                                                                                                                                                                                                                   | `0xca6c` (51820)                   |
| `WGUI_TABLE`                     | The default WireGuard table value settings                                                                                                                                                                                                                                                            | `auto`                             |
| `WGUI_CONFIG_FILE_PATH`          | The default WireGuard config file path used in global settings                                                                                                                                                                                                                                        | `/etc/wireguard/wg0.conf`          |
| `WGUI_LOG_LEVEL`                 | The default log level. Possible values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `OFF`                                                                                                                                                                                                                       | `INFO`                             |
| `WG_CONF_TEMPLATE`               | The custom `wg.conf` config file template. Please refer to our [default template](https://github.com/ngoduykhanh/wireguard-ui/blob/master/templates/wg.conf)                                                                                                                                          | N/A                                |
| `EMAIL_FROM_ADDRESS`             | The sender email address                                                                                                                                                                                                                                                                              | N/A                                |
| `EMAIL_FROM_NAME`                | The sender name                                                                                                                                                                                                                                                                                       | `WireGuard UI`                     |
| `SENDGRID_API_KEY`               | The SendGrid api key                                                                                                                                                                                                                                                                                  | N/A                                |
| `SENDGRID_API_KEY_FILE`          | Optional filepath for the SendGrid api key. Leave `SENDGRID_API_KEY` blank to take effect                                                                                                                                                                                                             | N/A                                |
| `SMTP_HOSTNAME`                  | The SMTP IP address or hostname                                                                                                                                                                                                                                                                       | `127.0.0.1`                        |
| `SMTP_PORT`                      | The SMTP port                                                                                                                                                                                                                                                                                         | `25`                               |
| `SMTP_USERNAME`                  | The SMTP username                                                                                                                                                                                                                                                                                     | N/A                                |
| `SMTP_PASSWORD`                  | The SMTP user password                                                                                                                                                                                                                                                                                | N/A                                |
| `SMTP_PASSWORD_FILE`             | Optional filepath for the SMTP user password. Leave `SMTP_PASSWORD` blank to take effect                                                                                                                                                                                                              | N/A                                |
| `SMTP_AUTH_TYPE`                 | The SMTP authentication type. Possible values: `PLAIN`, `LOGIN`, `NONE`                                                                                                                                                                                                                               | `NONE`                             |
| `SMTP_ENCRYPTION`                | The encryption method. Possible values: `NONE`, `SSL`, `SSLTLS`, `TLS`, `STARTTLS`                                                                                                                                                                                                                    | `STARTTLS`                         |
| `SMTP_HELO`                      | Hostname to use for the HELO message. smtp-relay.gmail.com needs this set to anything but `localhost`                                                                                                                                                                                                 | `localhost`                        |
| `TELEGRAM_TOKEN`                 | Telegram bot token for distributing configs to clients                                                                                                                                                                                                                                                | N/A                                |
| `TELEGRAM_ALLOW_CONF_REQUEST`    | Allow users to get configs from the bot by sending a message                                                                                                                                                                                                                                          | `false`                            |
| `TELEGRAM_FLOOD_WAIT`            | Time in minutes before the next conf request is processed                                                                                                                                                                                                                                             | `60`                               |
| `FCM_CREDENTIALS_FILE`           | Absolute path to the Firebase **service account** JSON used to send **FCM push** notifications (Android app tokens). If empty, `GOOGLE_APPLICATION_CREDENTIALS` is used instead. If neither resolves to a readable file, push is disabled. **Not** the same file as the app's `google-services.json`. | N/A                                |
| `GOOGLE_APPLICATION_CREDENTIALS` | Standard Google env: path to the **same** service account JSON as above. Used when `FCM_CREDENTIALS_FILE` is unset.                                                                                                                                                                                   | N/A                                |


### Firebase Cloud Messaging (FCM)

The server can send **push notifications** (e.g. peer created/removed/enabled/disabled, tunnel up/down) to devices that register an FCM token. Implementation lives in the `pushnotify` package. **FCM itself has no per-message charge** in typical Firebase usage; you still need a Firebase project and a service account for the Admin SDK.

#### Server setup

1. Open **[Firebase Console](https://console.firebase.google.com/)** → select **your project** → **Project settings** (gear icon) → tab **Service accounts**.
2. Under **Firebase Admin SDK** (wording may vary), choose **Node.js** or any language — what you need is **Generate new private key** (sometimes **Manage service account permissions** opens Google Cloud; the same key is created from the Firebase page’s **Generate new private key** button). Confirm the download; you get a single **`.json`** file.
3. Verify the file looks like a Google **service account key**: it contains **`"type": "service_account"`**, **`"project_id"`**, **`"private_key"`**, and **`"client_email"`**. That file is what **`FCM_CREDENTIALS_FILE`** / **`GOOGLE_APPLICATION_CREDENTIALS`** must point to — **not** `google-services.json` from the Android app.
4. Copy the JSON to the WireGuard UI host only (e.g. **`/etc/wireguard-ui/firebase-service-account.json`**). **Do not commit it.** Restrict access (`chmod 600` or `640` with a dedicated group, owned by the **`wireguard-ui`** process user).
5. Set **`FCM_CREDENTIALS_FILE`** to that absolute path (recommended) or **`GOOGLE_APPLICATION_CREDENTIALS`** to the same path (used when `FCM_CREDENTIALS_FILE` is empty).
6. If the server logs errors about an **API not enabled**, in **[Google Cloud Console](https://console.cloud.google.com/)** for the **same** `project_id` open **APIs & services → Enabled APIs** and enable **Firebase Cloud Messaging API** (FCM HTTP v1 uses it).
7. Restart wireguard-ui. You should see a log line such as **`FCM enabled`**. If credentials are missing or invalid, push stays off and an error is logged. **Rotate** (revoke old key, generate a new JSON) if the file may have leaked.

**Same project as the Android app:** The `project_id` in this JSON should match the Firebase project where you added the Android app and downloaded **`google-services.json`**. Two different files — one for the **server** (service account), one for the **Gradle client** (client config).

#### Project ID

The Firebase Go SDK needs a **Google Cloud / Firebase project ID**. It is normally taken from the `**project_id`** field inside the service account JSON. If you see `**project ID is required`** (or similar) in logs, set one of:


| Variable               | Purpose                                                              |
| ---------------------- | -------------------------------------------------------------------- |
| `FIREBASE_PROJECT_ID`  | Explicit Firebase/GCP project ID (highest precedence in app config). |
| `GOOGLE_CLOUD_PROJECT` | Same intent; common on GCP VMs.                                      |
| `GCLOUD_PROJECT`       | Same intent; legacy/alternate env name.                              |


Ensure the JSON file is the **service account key** from Firebase (it always contains `"type": "service_account"` and `"project_id"`).

#### Not the Android client file

- `**google-services.json`** is only for the **Android app** (Flutter `android/app/`). The **wireguard-ui server does not read it.** Server-side sending uses only the **service account** JSON from step 2.

#### Registration HTTP API

Authenticated JSON endpoints (same session cookies as the rest of the UI):


| Method | Path                              | Body                                                        |
| ------ | --------------------------------- | ----------------------------------------------------------- |
| `POST` | `{BASE_PATH}/api/push/register`   | `{"token":"<FCM registration token>","platform":"android"}` |
| `POST` | `{BASE_PATH}/api/push/unregister` | `{"token":"<FCM registration token>"}`                      |


Registered tokens are persisted under the server DB directory (e.g. `**push_tokens.json`** next to other JSON store files).

#### Rate limiting

Outbound FCM sends are **rate-limited per device token** (for example **at most 3 notifications per minute per token**) to avoid flooding.

#### Flutter Android client

Configure Firebase for the app package name, place `**google-services.json`** in `**android/app/`**, and enable push in the app; see the companion repo `**wireguard-ui-android-client`** README.

### Session idle timeout (**Settings** → **Session & security**)

In the UI, **Session idle timeout (minutes)** is stored as `session_timeout_minutes` (integer). **Always use whole minutes—not seconds.**


| Item                       | Detail                                                                                                                                                                                                          |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Unit**                   | **Minutes**, range **5-1440** (about 24 h max). Example: enter `30` for ~30 minutes.                                                                                                                            |
| **Behavior**               | **Idle logout:** after no authenticated HTTP request for longer than this time, the session is invalid (each request resets the idle clock). Applies to browsing and API endpoints that enforce `ValidSession`. |
| **When it applies**        | After saving from **Settings** and confirming **Apply config**, new sessions use this value when users **log in again**. Log out or wait for expiry to observe the change immediately.                          |
| **Remember-me**            | If a finite timeout is set in global settings, the login checkbox no longer lengthens the session to 7 days.                                                                                                    |
| `**SESSION_MAX_DURATION`** | Separate hard cap on how long any session identity may persist (days from login), independent of idle timeout. See the env table above.                                                                         |


### Defaults for server configuration

These environment variables are used to control the default server settings used when initializing the database.


| Variable                          | Description                                                                                   | Default         |
| --------------------------------- | --------------------------------------------------------------------------------------------- | --------------- |
| `WGUI_SERVER_INTERFACE_ADDRESSES` | The default interface addresses (comma-separated-list) for the WireGuard server configuration | `10.252.1.0/24` |
| `WGUI_SERVER_LISTEN_PORT`         | The default server listen port                                                                | `51820`         |
| `WGUI_SERVER_POST_UP_SCRIPT`      | The default server post-up script                                                             | N/A             |
| `WGUI_SERVER_POST_DOWN_SCRIPT`    | The default server post-down script                                                           | N/A             |


### Defaults for new clients

These environment variables are used to set the defaults used in `New Client` dialog.


| Variable                                    | Description                                                                                     | Default     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------- | ----------- |
| `WGUI_DEFAULT_CLIENT_ALLOWED_IPS`           | Comma-separated-list of CIDRs for the `Allowed IPs` field. (default )                           | `0.0.0.0/0` |
| `WGUI_DEFAULT_CLIENT_EXTRA_ALLOWED_IPS`     | Comma-separated-list of CIDRs for the `Extra Allowed IPs` field. (default empty)                | N/A         |
| `WGUI_DEFAULT_CLIENT_USE_SERVER_DNS`        | Boolean value [`0`, `f`, `F`, `false`, `False`, `FALSE`, `1`, `t`, `T`, `true`, `True`, `TRUE`] | `true`      |
| `WGUI_DEFAULT_CLIENT_ENABLE_AFTER_CREATION` | Boolean value [`0`, `f`, `F`, `false`, `False`, `FALSE`, `1`, `t`, `T`, `true`, `True`, `TRUE`] | `true`      |


### Docker only

These environment variables only apply to the docker container.


| Variable              | Description                                                   | Default |
| --------------------- | ------------------------------------------------------------- | ------- |
| `WGUI_MANAGE_START`   | Start/stop WireGuard when the container is started/stopped    | `false` |
| `WGUI_MANAGE_RESTART` | Auto restart WireGuard when we Apply Config changes in the UI | `false` |


### Server UI (optional OS integration)

Gate optional privileged actions invoked from the **Server** page (binary or Docker—the process must run on Linux with adequate permissions where needed):


| Variable                                  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Default                                                                                                                                                                                                                                                                                       |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WGUI_ALLOW_SYSCTL_IP_FORWARD`            | When `true`, saving with **IPv4 forwarding (ip_forward)** may run `sysctl -w net.ipv4.ip_forward=1` / `...=0` on Linux. Without it, only the preference is stored in the database. Ignored outside Linux.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `false`                                                                                                                                                                                                                                                                                       |
| `WGUI_WG_SYNCCONF_AFTER_APPLY`            | When `true`, **Apply config** runs `**wg-quick strip                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | wg syncconf `** on Linux so the running WireGuard matches the written file (e.g. disabling a client removes its peer from the server without` wg-quick down/up`). Requires` wg`and`wg-quick`on`$PATH`. If unset or` false`, Apply only writes the file/hash and does not reload kernel state. |
| `WGUI_ALLOW_WG_QUICK`                     | When `true`, **Apply** can run `wg-quick` down/up and the **Server** page shows **Stop** / **Start** / **Restart**. If unset, wg-quick controls are **off**. Start with `WGUI_ALLOW_WG_QUICK=true` when you intend to restart the tunnel from the UI. Env values are trimmed before parsing.                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `false`                                                                                                                                                                                                                                                                                       |
| `WGUI_WG_RESTART_VIA_SYSTEMD`             | On Linux, **Apply** prefers `systemctl restart wg-quick@ifac` when that unit exists (`LoadState=loaded`), so `**journalctl -u wg-quick@wg0`** shows restarts like a manual systemd restart. If `false` or no systemd, uses `wg-quick down`/`up`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `true`                                                                                                                                                                                                                                                                                        |
| `WGUI_WGCONF_PENDING_WHEN_TUNNEL_STOPPED` | Linux: when Apply does **not** restart WireGuard while the netdev is absent/down (e.g. after **Stop**), the UI writes a side file next to `wg.conf` (suffix `.wgui-pending`) instead of overwriting the live `**WGUI_CONFIG_FILE_PATH`**. That avoids systemd `**.path`** units watching `wg.conf` that restart `wg-quick` on every save. `**wg-quick up**` or **Server › Start** merges the pending file into `wg.conf` first. Set `false` to always write `wg.conf` directly (legacy).                                                                                                                                                                                                                                                              | `true`                                                                                                                                                                                                                                                                                        |
| `WGUI_LOG_TAIL_PATH`                      | Optional absolute path to a log file shown in the **Logs** page. This variable is read-only: wireguard-ui does not write this file automatically.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | *(unset)*                                                                                                                                                                                                                                                                                     |
| `WGUI_WEBAUTHN_RP_ID`                     | Optional fixed WebAuthn RP ID (recommended behind reverse proxy/public domain). If unset, it is inferred from request host.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | *(auto)*                                                                                                                                                                                                                                                                                      |
| `WGUI_WEBAUTHN_RP_ORIGINS`                | Optional comma-separated allowed origins for Passkeys (example: `https://vpn.example.com,https://admin.example.com`). If unset, origin is inferred per request.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | *(auto)*                                                                                                                                                                                                                                                                                      |
| `WGUI_WEBAUTHN_RP_DISPLAY_NAME`           | Optional WebAuthn RP display name shown by authenticators.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `WireGuard UI`                                                                                                                                                                                                                                                                                |
| `WGUI_ANDROID_PASSKEY_SHA256`             | One or more SHA-256 **signing-certificate fingerprints** of the Flutter/Android app (`./gradlew signingReport`), hex with or without colons, comma-separated. You may set this variable to an **absolute path** of a regular file (e.g. `/etc/wireguard-ui/android-SHA.secret`); the server reads the file contents as the same fingerprint string. The **wireguard-ui process user** must be able to read that file (e.g. `chgrp wireguard-ui` + `chmod 640`, or root-only if the service runs as root). Powers `**/.well-known/assetlinks.json`** (Digital Asset Links) and derives matching `**android:apk-key-hash:`** WebAuthn origins for native Android assertions. Unset ⇒ assetlinks endpoint returns 404 / no Android APK origins appended. |                                                                                                                                                                                                                                                                                               |
| `WGUI_ANDROID_PASSKEY_PACKAGE`            | Android `applicationId` embedded in `**assetlinks.json`**. Omit to use `**com.wireguardui.wireguard_ui_client`**.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                               |


#### Troubleshooting: `wg-quick up` fails on `ip -6 route` / «Cannot find device wg0»

After toggling peers and **Start**, a failed half-bridge can leave routing in an odd state; the UI now runs `**wg-quick down`** (ignored if already down), waits briefly, then `**wg-quick up`**, and retries once if the first `up` still errors. If it persists, exclude `**wg0`** from **NetworkManager** / **systemd-networkd**, and ensure IPv6 is consistent (either working or intentionally off) with the `**Address`** line in `**wg.conf`**.

#### `WGUI_LOG_TAIL_PATH` quick setup (systemd)

Use this when you want the **Logs** page to also show a custom application log file.

1. Add environment variable to your wireguard-ui service:

```ini
[Service]
Environment="WGUI_LOG_TAIL_PATH=/var/log/wireguard-ui.log"
```

1. Ensure file exists and is readable by the service user:

```bash
sudo touch /var/log/wireguard-ui.log
sudo chmod 640 /var/log/wireguard-ui.log
```

1. (Recommended) append service stdout/stderr to that file:

```ini
[Service]
StandardOutput=append:/var/log/wireguard-ui.log
StandardError=append:/var/log/wireguard-ui.log
```

1. Reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart wireguard-ui
```

1. Verify:

```bash
sudo systemctl show wireguard-ui -p Environment
sudo tail -n 50 /var/log/wireguard-ui.log
```

> Note: The Logs page now also includes `systemctl status wg-quick@<iface>` and recent `journalctl` output. `WGUI_LOG_TAIL_PATH` is only for the optional file section.

> **Passkeys:** `WGUI_WEBAUTHN_*` and `WGUI_ANDROID_PASSKEY_*` are listed in the [Server UI](#server-ui-optional-os-integration) table above. Full setup (browser and Android app, reverse proxy, HTTPS) is in [Passkeys (WebAuthn)](#passkeys-webauthn).

## Passkeys (WebAuthn)

Passwordless login for the web UI and the [wireguard-ui-android-client](https://github.com/Skyline-core/wireguard-ui-android-client) app. Enable **Passkeys** under **Global settings**, **Apply config**, then enroll credentials under **Profile** or **Users**.

Related environment variables: `WGUI_WEBAUTHN_RP_ID`, `WGUI_WEBAUTHN_RP_ORIGINS`, `WGUI_WEBAUTHN_RP_DISPLAY_NAME`, `WGUI_ANDROID_PASSKEY_SHA256`, `WGUI_ANDROID_PASSKEY_PACKAGE` (see [Server UI (optional OS integration)](#server-ui-optional-os-integration)).

### WebAuthn behind reverse proxy (systemd example)

If you use a public domain and/or reverse proxy (Nginx, Caddy, Traefik, Cloudflare Tunnel), define a fixed WebAuthn RP ID and allowed origins. Add the following under `**[Service]**` (for example with `**systemctl edit wireguard-ui**` or entries in the same `**EnvironmentFile=**` you use in **[systemd: install and enable the web service](#systemd-install-and-enable-the-web-service)**):

```ini
[Service]
Environment="WGUI_WEBAUTHN_RP_ID=vpn.example.com"
Environment="WGUI_WEBAUTHN_RP_ORIGINS=https://vpn.example.com"
Environment="WGUI_WEBAUTHN_RP_DISPLAY_NAME=WireGuard UI"
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart wireguard-ui
```

Notes:

- `WGUI_WEBAUTHN_RP_ID` must match your effective login domain.
- `WGUI_WEBAUTHN_RP_ORIGINS` accepts comma-separated values for multi-origin setups.
- Passkeys require `https://` in production (browsers only allow non-HTTPS for localhost).

### Android app passkeys (companion Flutter client — Credential Manager)

The Flutter Android companion app calls the same WireGuard UI WebAuthn JSON endpoints (`**POST**` `**{BASE_PATH}/api/passkeys/login/begin**`, `**/finish**`). Android **Credential Manager** still verifies **Digital Asset Links** independently: it downloads `**https://<rpId>/.well-known/assetlinks.json`** and checks package name + signing certificate fingerprints against your app install.

Assertion signatures include `**Origin`** inside `**clientDataJSON`**. Browser users send origins like `**https://vpn.example.com`**. Native Android sends `**android:apk-key-hash:<base64url(SHA-256(signing-cert-digest))>**`. The `**go-webauthn**` verifier must therefore allow both your HTTPS origins and the APK-hash origin — WireGuard UI appends APK-hash origins whenever `**WGUI_ANDROID_PASSKEY_SHA256**` is set.

**Suggested end-to-end flow**

1. **Browser first:** In WireGuard UI, enable **Passkeys** under Global settings and **Apply config**. Open the panel URL (example: `**https://vpn.example.net/wg`** if `BASE_PATH` is `**/wg`**), visit Profile (or Administrator → Users), and enroll at least one passkey per account that should unlock the Android app. That registers credentials bound to `**WGUI_WEBAUTHN_RP_ID`** (or inferred host).
2. **Server env:** Set `**WGUI_WEBAUTHN_RP_ORIGINS`** (comma-separated `**https://`** origins visitors actually see) plus `**WGUI_WEBAUTHN_RP_ID`** when you rely on proxies or internal hostnames — they must mirror the HTTPS hostname tied to `**assetlinks.json`**. Populate `**WGUI_ANDROID_PASSKEY_SHA256**` from `./gradlew signingReport`, matching whichever keystore ships on devices, and set `**WGUI_ANDROID_PASSKEY_PACKAGE**` if Gradle `**applicationId**` deviates from the default `**com.wireguardui.wireguard_ui_client**`.
3. **Reverse proxy:** Route `**/.well-known/assetlinks.json`** on the panel hostname back to WireGuard UI (see examples below).
4. **App:** Configure base URL/base path matching your API prefix. Fill **Passkey origin** if the HTTPS hostname where you enrolled passkeys differs from the API `**Host`** (LAN IP/API gateway case). Prefer **Username** + passkey together if the credential is not discoverable (common for web-created passkeys unless you mandated resident/discoverable enrollment).

**Symptoms resolved by proper setup**


| Symptom                                                                                   | Typical cause                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `**RP ID cannot be validated`** (Credential Manager DOM error)                            | Missing or inaccessible `**https://<rpId>/.well-known/assetlinks.json`** (**404**, auth wall, redirects). Proxies forwarding only `**{BASE_PATH}`** strand this path unless you terminate `**/.well-known`** upstream—see **[Digital Asset Links](https://developers.google.com/digital-asset-links/v1/getting-started)** tooling to validate statements externally. |
| `**Invalid passkey`** after tapping a credential but **Digital Asset Links** already pass | Older servers missing APK-hash `**RPOrigins`**, malformed assertion body, mismatched `**WGUI_ANDROID_PASSKEY_SHA256`** vs APK, or `**begin`/`finish` session loss** — see cookie note below.                                                                                                                                                                         |
| `**HTTP 405`** (`curl -I` only) against assetlinks                                        | `curl -I` issues **HEAD**. WireGuard UI implements **HEAD** + **GET**; if you proxy strips HEAD pick **GET** (`**curl -sS`**).                                                                                                                                                                                                                                       |


**Server configuration checklist**

1. `**WGUI_ANDROID_PASSKEY_SHA256`** — fingerprint(s) comma-separated (**hex**, with or without colons); or an **absolute path** to a file whose contents are that string (readable by the **wireguard-ui** process user). Obtain fingerprints from the Flutter Android project: **`cd android && ./gradlew :app:signingReport`**, then use the **`debug`** SHA-256 when you install debug-signed builds (dev APK) and the **`release`** SHA-256 when you install production-signed APK/AAB — **they differ because signing certs differ**. In Android Studio: **Gradle → Tasks → android → signingReport**. Add multiple hashes comma-separated when some devices still use another signing certificate.
2. `**WGUI_ANDROID_PASSKEY_PACKAGE`** — optional `**applicationId`**, defaults to `**com.wireguardui.wireguard_ui_client`** inside `**assetlinks.json**`.
3. **Reverse proxy exposes host-root asset links** proxying `**https://<hostname>/.well-known/assetlinks.json`** to WireGuard UI's `**http://backend:PORT/.well-known/assetlinks.json`**. `**https://hostname/wg/.well-known`** is **ignored** by Android's association crawler.
4. **Mirror workaround:** If you truly cannot terminate `**/.well-known`** directly on WireGuard UI, `**GET https://vpn.example.net/wg/.well-known/assetlinks.json`** (duplicate route emitted when `**BASE_PATH=/wg`**; adjust path for your `**BASE_PATH`**) returns the identical JSON blob you can synchronize to `**https://vpn.example.net/.well-known/assetlinks.json**` elsewhere.

**Behavior implemented in WireGuard UI**


| Mechanism                                             | Role                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `**GET` / `HEAD`** `**/.well-known/assetlinks.json`** | Issues Digital Asset Links JSON including `**delegate_permission/common.get_login_creds`** plus `**delegate_permission/common.handle_all_urls`**.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `**X-WGUI-WebAuthn-Public-Origin**`                   | Optional HTTPS-only hint validated against configured origins; forces rp host alignment when mobiles talk to `**https://LAN:port/wg**` but passkeys bind to `**https://vpn.example.com**`. If it disagrees with `**WGUI_WEBAUTHN_RP_ID**`, the hinted public host wins **for configuring WebAuthn** so Credential Manager `**rp.id`** verification matches `**assetlinks`**. Never trust arbitrary hosts blindly — values must already be admitted via `**WGUI_WEBAUTHN_RP_ORIGINS`**, `**WGUI_WEBAUTHN_RP_ID` hostname match**, or the inferred default origin header. |
| `**android:apk-key-hash`** derived origins            | For every SHA-256 entry in `**WGUI_ANDROID_PASSKEY_SHA256`**, append `**android:apk-key-hash:`** + URL-safe Base64 (no padding) of the raw digest to `**RPOrigins**`.                                                                                                                                                                                                                                                                                                                                                                                                   |
| `**RPAllowCrossOrigin`**                              | Enabled whenever `**WGUI_ANDROID_PASSKEY_SHA256`** is non-empty so Credential Manager payloads that declare `**crossOrigin`** in `**clientDataJSON**` pass verification once origins match.                                                                                                                                                                                                                                                                                                                                                                             |


**Reverse proxy snippets**

**Caddy (keep `/.well-known` on the apex host while `{BASE_PATH}` serves the UI — e.g. `/wg`)**

```caddyfile
vpn.example.net {
	handle /.well-known/assetlinks.json {
		reverse_proxy 127.0.0.1:5000
	}
	handle /wg* {
		reverse_proxy 127.0.0.1:5000
	}
}
```

Replace `**127.0.0.1:5000**` with your `**BIND_ADDRESS**` target (`docker` internal hostname, upstream socket, etc.).

**Apache / legacy `ProxyPass`**

Enable `**mod_proxy**` + `**proxy_http**` (Debian/Ubuntu: `a2enmod proxy proxy_http`). Example:

```apache
SSLProxyEngine on
ProxyPass        /.well-known/assetlinks.json http://127.0.0.1:5000/.well-known/assetlinks.json
ProxyPassReverse /.well-known/assetlinks.json http://127.0.0.1:5000/.well-known/assetlinks.json
```

Place specific statements **above** wildcard `**ProxyPass /`** directives.

Equivalent **Nginx** pattern:

```nginx
location = /.well-known/assetlinks.json {
    proxy_pass http://127.0.0.1:5000/.well-known/assetlinks.json;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Verification (expect `**200**` and JSON body):

```bash
curl -sSIL https://vpn.example.net/.well-known/assetlinks.json
curl -sS  https://vpn.example.net/.well-known/assetlinks.json
# pipe through jq locally if installed for readability
```

**Login session cookie**

The `**login/begin`** response sets a `**session`** cookie tying server-side `**SessionData`** to `**login/finish`**. The companion Flutter client keeps a Dio cookie jar; ensure reverse proxies propagate `**Cookie` / `Set-Cookie**` without stripping attributes. Tune `**WGUI_SESSION_COOKIE_***` when browsers or SPA clients authenticate cross-site (`SameSite=None` + `Secure`).

Logs: failing `**finish**` emits `**WARN [passkeys] login finish rejected ...**` with the verifier error (**origin**, **challenge**, **signature**) — correlate with timestamps while reproducing mobile flows.

Companion UX reminders:

- `**Passkey origin`** on the Flutter login sheet maps straight to `**X-WGUI-WebAuthn-Public-Origin`** whenever the HTTPS hostname used during browser enrollment differs from the API `**Host`**.
- Supply `**Username`** + passkey for accounts whose authenticators are **non-discoverable** (typical hybrid web enrollments unless you forced resident keys).
- After rotating TLS/proxy fingerprints, run `**adb shell pm verify-app-links --re-verify com.wireguardui.wireguard_ui_client`** so Android re-fetches statements (swap package id if customized).

Additional documentation lives in `**wireguard-ui-android-client`** `README.md` (mobile-focused recap).

### Caddy + Dynamic DNS (No-IP): quick HTTPS so Passkeys work

Browsers treat Passkeys/WebAuthn as **[secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)** (`https://` on a hostname, or `http://localhost`). Plain `http://<your-ip>` is **not** enough. Use a hostname (No-IP, DuckDNS, etc.), forward ports **80** and **443**, and terminate TLS with Caddy.

1. **No-IP (or similar)**
  Create `yourhost.ddns.net` (example), install the updater or rely on No-IP so the **A record** points to your **WAN** public IP.
2. **Firewall / router**
  Forward **TCP 80** and **TCP 443** from the internet to the machine that runs Caddy (required for Let's Encrypt HTTP-01 by default).
3. **Install Caddy**
  Follow [Caddy install docs](https://caddyserver.com/docs/install) for your distro (official repo or package).
4. `**Caddyfile`** (minimal reverse proxy to WireGuard UI on loopback):
  ```caddyfile
   yourhost.ddns.net {
       encode gzip
       reverse_proxy 127.0.0.1:5000
   }
  ```
   Replace `yourhost.ddns.net` with your hostname and `**5000**` with the port where `wireguard-ui` listens (`BIND_ADDRESS`, e.g. `:5000` or `127.0.0.1:5000`).
5. **(Optional, recommended)** Listen only on localhost so only Caddy exposes HTTPS:
  ```bash
   BIND_ADDRESS=127.0.0.1:5000 ./wireguard-ui
  ```
6. **Restart Caddy**, then open `**https://yourhost.ddns.net`** and confirm the browser shows a **valid lock** (no certificate warnings).
7. `**wireguard-ui` systemd** — set RP ID/origin to match **exactly** what users type in the browser:
  ```ini
   [Service]
   Environment="WGUI_WEBAUTHN_RP_ID=yourhost.ddns.net"
   Environment="WGUI_WEBAUTHN_RP_ORIGINS=https://yourhost.ddns.net"
  ```
   Then `daemon-reload` and `restart wireguard-ui`.
8. **Inside the UI** — **Settings** → enable **Passkeys** → **Apply config**. Then **Administration → Users**: register a passkey per user. The login page will offer **Sign in with Passkey** once enabled.

If HTTPS still fails behind NAT, verify port 80 reaches Caddy on first certificate issuance; use `journalctl -u caddy -f` on errors.

## Auto restart WireGuard daemon

WireGuard-UI only takes care of configuration generation. On Linux you can enable in-process `wg syncconf` after apply (see variables above), or use systemd to watch for changes and restart the
service. Following is an example:

> **Note:** The **systemd** block below does **not** start the `wireguard-ui` web process. It only runs `systemctl restart wg-quick@wg0` when `wg0.conf` is modified on disk. The UI binary is a separate program (see [Run WireGuard UI](#run-wireguard-ui) and [systemd: install and enable the web service](#systemd-install-and-enable-the-web-service)).

### systemd: install and enable the web service

This section is about the **wireguard-ui HTTP process** (the web UI), not the optional `**wg-quick@`** watcher described later.

#### What systemd must provide

1. **Working directory** — The app opens its JSON store at `**./db`** relative to the current working directory (`jsondb.New("./db")` in `main.go`). The unit **must** set `WorkingDirectory` to a persistent directory owned by the service user (e.g. `/var/lib/wireguard-ui`). If you omit this, the database lands wherever systemd’s default cwd is (often `/` or `/root`), which is easy to misplace or permission incorrectly.
2. **Binary** — Install the release binary (or your own build after `./prepare_assets.sh`) to a fixed path, e.g. `**/usr/local/bin/wireguard-ui`**, mode `0755`.
3. **Environment** — All knobs (`BASE_PATH`, `BIND_ADDRESS`, `SESSION_SECRET`, `WGUI_*`, `FCM_CREDENTIALS_FILE`, etc.) are ordinary **process environment variables**. Set them with `Environment=` lines in the unit, or load a file with `EnvironmentFile=`.

For an interactive first-time install (paths, secrets, optional Caddy), use [Quick install (scripted setup)](#quick-install-scripted-setup) instead of copying the unit by hand.

#### Register the service (step by step)

1. **Create an unprivileged account and data directory** (recommended). The home directory doubles as `**WorkingDirectory`** / database location:
  ```bash
   sudo useradd --system --create-home --home-dir /var/lib/wireguard-ui \
     --shell /usr/sbin/nologin --user-group wireguard-ui
   sudo chmod 750 /var/lib/wireguard-ui
  ```
   If the user already exists, ensure `**/var/lib/wireguard-ui**` exists and is owned by `**wireguard-ui:wireguard-ui**` with mode `**0750**`.
2. **Install the binary**:
  ```bash
   sudo install -m 0755 wireguard-ui /usr/local/bin/wireguard-ui
  ```
3. **Optional config directory** for secrets on disk (session key, Firebase JSON, Android SHA file, etc.):
  ```bash
   sudo mkdir -p /etc/wireguard-ui
   sudo chown root:wireguard-ui /etc/wireguard-ui
   sudo chmod 750 /etc/wireguard-ui
  ```
   Place secret files here and grant the **service user** read access (e.g. `chmod 640` and group `wireguard-ui`, or ownership `wireguard-ui:wireguard-ui` as appropriate). If a path is unreadable by the process user, features that read that file (session encryption, FCM, passkey asset links) will fail at runtime.
4. **Environment file** — systemd reads `**KEY=value`** lines from `EnvironmentFile=` (comments with `#` allowed). You do **not** need `export`. Example `**/etc/default/wireguard-ui`** (Debian/Ubuntu naming is common; the path is arbitrary as long as the unit references it):
  ```text
   BIND_ADDRESS=127.0.0.1:5000
   BASE_PATH=wg
   SESSION_SECRET_FILE=/etc/wireguard-ui/session.secret
  ```
   Point `SESSION_SECRET` **or** `SESSION_SECRET_FILE` at a strong secret (see the environment table above). Same idea for `WGUI_PASSWORD_FILE`, `FCM_CREDENTIALS_FILE`, and `**WGUI_ANDROID_PASSKEY_SHA256`** (inline hex **or** absolute path to a file whose contents are the fingerprint string).
5. **Unit file** — Create `**/etc/systemd/system/wireguard-ui.service`**:

```ini
[Unit]
Description=WireGuard UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wireguard-ui
Group=wireguard-ui
WorkingDirectory=/var/lib/wireguard-ui
EnvironmentFile=-/etc/default/wireguard-ui
ExecStart=/usr/local/bin/wireguard-ui
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

   The `-` prefix on `**EnvironmentFile=-/etc/default/wireguard-ui**` means “ignore if missing” so the unit still parses before you create the file. You can instead use `**/etc/wireguard-ui.env**` or multiple `Environment="KEY=value"` lines for a minimal setup.

1. **Reload systemd and start**:
  ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now wireguard-ui
   sudo systemctl status wireguard-ui
  ```
2. **Logs**:
  ```bash
   journalctl -u wireguard-ui -f
  ```

#### WireGuard config and `wg-quick` / `systemctl`

If the UI should **write** `wg0.conf` (default `**/etc/wireguard/wg0.conf`**) or run `**wg-quick`** / `**systemctl restart wg-quick@…**`, the `**wireguard-ui` user** must be allowed to do so on your distribution (group membership on `/etc/wireguard`, `sudoers` for specific commands, or a documented choice to run the service as root — discouraged). There is no single recipe across distros; tighten permissions after verifying **Apply config** and optional `**WGUI_ALLOW_WG_QUICK`** / `**WGUI_WG_RESTART_VIA_SYSTEMD`** behaviour.

#### Example unit without `EnvironmentFile` (inline bind only)

The app stores its JSON database under `**./db` relative to the process working directory**, so `WorkingDirectory` is mandatory for a predictable data path.

```ini
[Unit]
Description=WireGuard UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wireguard-ui
Group=wireguard-ui
WorkingDirectory=/var/lib/wireguard-ui
Environment="BIND_ADDRESS=127.0.0.1:5000"
ExecStart=/usr/local/bin/wireguard-ui
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then `systemctl daemon-reload` and `systemctl enable --now wireguard-ui` as above.

### Using systemd (restart `wg-quick` when config file changes)

Create `/etc/systemd/system/wgui.service`

```bash
cd /etc/systemd/system/
cat << EOF > wgui.service
[Unit]
Description=Restart WireGuard
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart wg-quick@wg0.service

[Install]
RequiredBy=wgui.path
EOF
```

Create `/etc/systemd/system/wgui.path`

```bash
cd /etc/systemd/system/
cat << EOF > wgui.path
[Unit]
Description=Watch /etc/wireguard/wg0.conf for changes

[Path]
PathModified=/etc/wireguard/wg0.conf

[Install]
WantedBy=multi-user.target
EOF
```

Apply it

```sh
systemctl enable wgui.{path,service}
systemctl start wgui.{path,service}
```

### Using openrc

Create `/usr/local/bin/wgui` file and make it executable

```sh
cd /usr/local/bin/
cat << EOF > wgui
#!/bin/sh
wg-quick down wg0
wg-quick up wg0
EOF
chmod +x wgui
```

Create `/etc/init.d/wgui` file and make it executable

```sh
cd /etc/init.d/
cat << EOF > wgui
#!/sbin/openrc-run

command=/sbin/inotifyd
command_args="/usr/local/bin/wgui /etc/wireguard/wg0.conf:w"
pidfile=/run/${RC_SVCNAME}.pid
command_background=yes
EOF
chmod +x wgui
```

Apply it

```sh
rc-service wgui start
rc-update add wgui default
```

### Using Docker

Set `WGUI_MANAGE_RESTART=true` to manage Wireguard interface restarts.
Using `WGUI_MANAGE_START=true` can also replace the function of `wg-quick@wg0` service, to start Wireguard at boot, by
running the container with `restart: unless-stopped`. These settings can also pick up changes to Wireguard Config File
Path, after restarting the container. Please make sure you have `--cap-add=NET_ADMIN` in your container config to make
this feature work.

## Continuous integration (GitHub Actions)

Workflow **`.github/workflows/lint.yml`** (on **`master`**) runs:

- **`go vet ./...`** and **`go test ./... -short`**
- **`govulncheck`** via **`go run golang.org/x/vuln/cmd/govulncheck@latest ./...`**
- **golangci-lint** (see **`.golangci.yml`**)

Go is installed from **`go.mod`** (**`setup-go`** with **`go-version-file`**).

## Build

### Build docker image

Go to the project root directory and run the following command:

```sh
docker build --build-arg=GIT_COMMIT=$(git rev-parse --short HEAD) -t wireguard-ui .
```

or

```sh
docker compose build --build-arg=GIT_COMMIT=$(git rev-parse --short HEAD)
```

:information_source: A container image is available on [Docker Hub](https://hub.docker.com/r/ngoduykhanh/wireguard-ui)
which you can pull and use

```
docker pull ngoduykhanh/wireguard-ui
```

### Build binary file

Prepare the assets directory

```sh
./prepare_assets.sh
```

Then build your executable

```sh
go build -o wireguard-ui
```

## License

MIT. See [LICENSE](https://github.com/ngoduykhanh/wireguard-ui/blob/master/LICENSE).

## Support

If you like the project and want to support it, you can *buy me a coffee* ☕
