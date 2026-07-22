#!/usr/bin/env bash
#
# Guided production setup on Linux for WireGuard UI: installs the binary to
# /usr/local/bin/wireguard-ui (compile, repo artifact, or copy), registers a systemd
# unit for boot-time start, optional packages (openssl, wireguard-tools, Caddy), and
# secret/env files (session, Android passkey SHA, optional FCM JSON).
# Run as root or with sudo. Does not overwrite existing files without prompting.
#
# Usage: sudo ./setup-linux-production.sh

set -euo pipefail

IFS=$'\n\t'

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
RST='\033[0m'

die() {
  printf '%b%s%b\n' "$RED" "Error: $*" "$RST" >&2
  exit 1
}

info() { printf '%b%s%b\n' "$GRN" "$*" "$RST"; }
warn() { printf '%b%s%b\n' "$YLW" "$*" "$RST"; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Ejecutá este script con sudo o como root."
  fi
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

prompt() {
  local msg="$1"
  local default="${2:-}"
  local val
  if [[ -n "$default" ]]; then
    read -r -p "$(printf '%s [%s]: ' "$msg" "$default")" val || true
    val="$(trim "${val}")"
    if [[ -z "$val" ]]; then
      printf '%s' "$default"
    else
      printf '%s' "$val"
    fi
  else
    read -r -p "$(printf '%s: ' "$msg")" val || true
    printf '%s' "$(trim "${val}")"
  fi
}

yes_no() {
  local msg="$1"
  local default_n="${2:-y}"
  local hint="s/N"
  [[ "$default_n" == "y" ]] && hint="S/n"
  while true; do
    read -r -p "${msg} [${hint}]: " a || true
    a="$(trim "${a}")"
    a="${a,,}"
    if [[ -z "$a" ]]; then
      [[ "$default_n" == "y" ]] && return 0
      [[ "$default_n" == "n" ]] && return 1
    fi
    case "$a" in
      s|si|sí|y|yes) return 0 ;;
      n|no) return 1 ;;
      *) warn "Respondé s o n." ;;
    esac
  done
}

ensure_dir() {
  install -d -m "$2" -o "$3" -g "$4" "$1"
}

random_hex() {
  local n="${1:-32}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$n"
  else
    head -c "$(("$n" / 2))" /dev/urandom | xxd -p -c "$(("$n" / 2))"
  fi
}

normalize_base_path() {
  local p="$1"
  p="$(trim "$p")"
  p="${p#/}"
  p="${p%/}"
  if [[ -z "$p" ]]; then
    printf '/'
  else
    printf '/%s' "$p"
  fi
}

# First existing candidate binary in the repo tree (release artifact or local build).
find_repo_binary() {
  local root="$1"
  local c
  for c in \
    "$root/wireguard-ui-linux-arm64" \
    "$root/wireguard-ui-linux-amd64" \
    "$root/wireguard-ui" \
    "$root/dist/wireguard-ui"; do
    if [[ -f "$c" ]]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

# Install wireguard-ui executable to BIN_DST (compile, copy from repo, or copy custom path).
install_wireguard_binary() {
  local bin_dst="$1"
  local repo_root="$2"
  local installed=0
  local src prebuilt

  info "--- Instalación del binario → $bin_dst ---"

  if [[ -f "$bin_dst" ]]; then
    if ! yes_no "Ya existe $bin_dst. ¿Reemplazarlo?" "n"; then
      info "Se conserva el binario en $bin_dst."
      return 0
    fi
  fi

  install -d -m 0755 "$(dirname "$bin_dst")"

  if [[ -f "$repo_root/go.mod" ]]; then
    prebuilt="$(find_repo_binary "$repo_root" || true)"
    if [[ -n "$prebuilt" ]]; then
      if yes_no "¿Copiar el binario del repo ($prebuilt) a $bin_dst?" "y"; then
        install -Dm755 "$prebuilt" "$bin_dst"
        info "Binario instalado: $prebuilt → $bin_dst"
        installed=1
      fi
    fi
  fi

  if [[ "$installed" -eq 0 ]] && [[ -f "$repo_root/go.mod" ]]; then
    if yes_no "¿Compilar desde el código de este repo e instalar en $bin_dst?" "y"; then
      if yes_no "¿Ejecutar prepare_assets.sh antes del build?" "y"; then
        chmod +x "$repo_root/prepare_assets.sh" 2>/dev/null || true
        (cd "$repo_root" && bash ./prepare_assets.sh)
      fi
      if ! command -v go >/dev/null 2>&1; then
        die "Falta 'go' en el PATH para compilar."
      fi
      (cd "$repo_root" && go build -trimpath -o "$bin_dst" .)
      info "Binario compilado e instalado en $bin_dst"
      installed=1
    fi
  fi

  if [[ "$installed" -eq 0 ]]; then
    src="$(prompt "Ruta al ejecutable wireguard-ui a copiar (obligatorio si no compilaste)" "")"
    [[ -n "$src" ]] || die "Indicá un binario fuente o compilá desde el repo."
    [[ -f "$src" ]] || die "No existe el archivo: $src"
    install -Dm755 "$src" "$bin_dst"
    info "Binario instalado: $src → $bin_dst"
    installed=1
  fi

  [[ -f "$bin_dst" ]] || die "No se pudo instalar el binario en $bin_dst"
  chmod 755 "$bin_dst"
}

# Detect pkg manager binary on PATH (not full distro ID).
detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    printf '%s\n' apt
  elif command -v dnf >/dev/null 2>&1; then
    printf '%s\n' dnf
  elif command -v yum >/dev/null 2>&1; then
    printf '%s\n' yum
  elif command -v apk >/dev/null 2>&1; then
    printf '%s\n' apk
  else
    printf '%s\n' unknown
  fi
}

# openssl: secretos rand; curl: repos; gnupg: claves Caddy/Debian.
# wireguard-tools: wg, wg-quick (útil si WGUI_ALLOW_WG_QUICK).
install_recommended_pkgs() {
  local mgr="$1"
  case "$mgr" in
    apt)
      info "Instalación con apt-get (openssl ca-certificates curl gnupg wireguard-tools)…"
      apt-get update -qq
      apt-get install -y openssl ca-certificates curl gnupg wireguard-tools
      ;;
    dnf)
      info "Instalación con dnf (openssl curl gnupg2 wireguard-tools + ca-certificates)…"
      dnf install -y openssl curl gnupg2 wireguard-tools ca-certificates ||
        die "dnf install falló."
      ;;
    yum)
      info "Instalación con yum (openssl curl gnupg2 wireguard-tools ca-certificates)…"
      yum install -y openssl curl gnupg2 wireguard-tools ca-certificates ||
        die "yum install falló."
      ;;
    apk)
      info "Instalación con apk (openssl ca-certificates curl wireguard-tools)…"
      apk add --no-cache openssl ca-certificates curl wireguard-tools
      ;;
    *)
      warn "No hay apt-get/dnf/yum/apk: instalá manualmente openssl, ca-certificates, curl, herramientas WireGuard."
      return 1
      ;;
  esac
}

# Repo Cloudsmith estable de Caddy (Debian/Ubuntu + apt-get). Idempotente si ya está instalado.
ensure_caddy_apt_pkg() {
  if command -v caddy >/dev/null 2>&1; then
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    return 1
  fi
  if [[ "${DISTRO_DEBIANLIKE:-0}" -ne 1 ]]; then
    return 1
  fi
  info "Instalando paquete Caddy (repos oficiales)…"
  apt-get update -qq
  apt-get install -y debian-keyring debian-archive-keyring curl gnupg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  apt-get update -qq
  apt-get install -y caddy
}

# --- Main -----------------------------------------------------------------

require_root

info "=== Instalador guiado: WireGuard UI (systemd / secretos / Caddy opcional) ==="
warn "Revisá el README del proyecto sobre permisos (wg-quick, aplicar config, logs)."
echo

if yes_no "¿Este servidor es Debian/Ubuntu (apt)? Si no, se omitirá la instalación automática de Caddy pero podés usar el archivo generado más adelante." "n"; then
  DISTRO_DEBIANLIKE=1
else
  DISTRO_DEBIANLIKE=0
fi

echo
info "--- Paquetes complementarios ---"
warn "Útil tener openssl, TLS trust, curl, gpg y wg/wg-quick en el servidor."
if yes_no "¿Instalar paquetes recomendados para WireGuard UI (automático según el gestor detectado)?" "y"; then
  PKG_MGR="$(detect_pkg_mgr)"
  if [[ "$PKG_MGR" == "unknown" ]]; then
    warn "No detecté apt/dnf/yum/apk."
  else
    info "Gestor detectado: $PKG_MGR"
    install_recommended_pkgs "$PKG_MGR" || true
    info "Paquetes recomendados instalados (o gestor omitido)."
  fi
fi

if yes_no "¿Instalar ahora el paquete Caddy (reverse proxy HTTPS)? Solo automatizado si marcaste Debian/Ubuntu y existe apt-get." "n"; then
  if ! ensure_caddy_apt_pkg; then
    warn "No instalé Caddy automáticamente: podés hacerlo después o usar el bloque opcional HTTPS al final del script."
  else
    info "Caddy disponible como comando: $(command -v caddy)"
  fi
fi
echo

WG_HOME="$(prompt 'Directorio de secretos y archivos generados (env, Caddy, etc.)' '/etc/wireguard-ui')"
DATA_DIR="$(prompt 'Directorio de datos (base de datos ./db del programa = WorkingDirectory systemd)' '/var/lib/wireguard-ui')"
BIN_DST='/usr/local/bin/wireguard-ui'
if ! yes_no "¿Instalar el binario en $BIN_DST? (recomendado)" "y"; then
  BIN_DST="$(prompt 'Ruta alternativa del binario' '/usr/local/bin/wireguard-ui')"
fi
APP_USER="$(prompt 'Usuario del servicio systemd (root suele hacer falta si usás wg-quick desde la UI)' 'root')"
APP_GROUP="$APP_USER"

if [[ "$APP_USER" != "root" ]] && ! getent passwd "$APP_USER" >/dev/null; then
  if yes_no "El usuario '$APP_USER' no existe. ¿Crearlos como cuenta de sistema (sin login)?" "y"; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER" || die "No pude crear el usuario."
    APP_GROUP="$APP_USER"
    info "Usuario de sistema $APP_USER creado."
  else
    die "Creá el usuario antes de continuar o elegí otro valor."
  fi
fi

ensure_dir "$WG_HOME" 0750 "$APP_USER" "$APP_GROUP"
ensure_dir "$DATA_DIR" 0750 "$APP_USER" "$APP_GROUP"

REPO_ROOT="$(pwd)"
if [[ ! -f "$REPO_ROOT/go.mod" ]]; then
  warn "No hay go.mod en $REPO_ROOT; solo podrás copiar un binario ya compilado."
  REPO_ROOT=""
fi
install_wireguard_binary "$BIN_DST" "$REPO_ROOT"

BIND_LOOPBACK="$(prompt 'Bind local del proceso (ej. 127.0.0.1 si lo tapa Caddy, 0.0.0.0 si es directo)' '127.0.0.1:5000')"
if ! yes_no "¿Es correcto BIND_ADDRESS='$BIND_LOOPBACK'?" "y"; then
  BIND_LOOPBACK="$(prompt 'Nuevo BIND_ADDRESS (host:puerto ej. 0.0.0.0:5000)' "$BIND_LOOPBACK")"
fi

BASE_RAW="$(prompt 'BASE_PATH (sin barra inicial, ej: wg)' 'wg')"
BASE_PATH_NORM="$(normalize_base_path "$BASE_RAW")"

WGUI_ALLOW_WG_QUICK="false"
yes_no "¿Activar controles wg-quick desde la UI? (WGUI_ALLOW_WG_QUICK)" "y" && WGUI_ALLOW_WG_QUICK="true"

WGUI_SYNCCONF="false"
yes_no "¿Ejecutar wg syncconf después de aplicar wg.conf cuando sea posible? (WGUI_WG_SYNCCONF_AFTER_APPLY)" "y" && WGUI_SYNCCONF="true"

SESSION_FILE="$WG_HOME/session.secret"
if [[ ! -f "$SESSION_FILE" ]] || yes_no "Ya existe $SESSION_FILE. ¿Regenerar secreto de sesión?" "n"; then
  umask 077
  printf '%s' "$(random_hex 64)" >"$SESSION_FILE"
  chown "$APP_USER:$APP_GROUP" "$SESSION_FILE"
  chmod 600 "$SESSION_FILE"
  umask 022
  info "Creado $SESSION_FILE"
fi

LOG_TAIL="$(prompt 'Ruta de log opcional para cola desde la UI (WGUI_LOG_TAIL_PATH, puede quedar vacío)' '/var/log/wireguard-ui.log')"
if [[ -n "$LOG_TAIL" ]]; then
  touch "$LOG_TAIL" 2>/dev/null || true
  if [[ ! -f "$LOG_TAIL" ]]; then
    install -Dm644 /dev/null "$LOG_TAIL" || warn "No pude crear $LOG_TAIL manualmente después."
  fi
  chown "$APP_USER:$APP_GROUP" "$LOG_TAIL" 2>/dev/null || true
fi

ANDROID_SHA_FILE="$WG_HOME/android-SHA.secret"
ANDROID_SHA_VAL=""
PASSKEY_SETUP="false"
WEBAUTH_RP_ID=""
WEBAUTH_ORIGINS=""
WEBAUTH_DISP="WireGuard UI"
ANDROID_PKG=""

if yes_no "¿Configurás Passkeys/Android (necesita HTTPS público típicamente)?" "n"; then
  PASSKEY_SETUP="true"
  WEBAUTH_RP_ID="$(prompt 'WGUI_WEBAUTHN_RP_ID (hostname verificado por el navegador, sin https)' 'vpn.example.net')"
  WEBAUTH_ORIGINS="$(prompt 'WGUI_WEBAUTHN_RP_ORIGINS separados por coma (ej https://vpn.example.net,https://www.vpn.example.net)' '')"
  WEBAUTH_DISP="$(prompt 'WGUI_WEBAUTHN_RP_DISPLAY_NAME' 'WireGuard UI')"
  ANDROID_PKG="$(prompt 'WGUI_ANDROID_PASSKEY_PACKAGE (applicationId Android, opcional)' 'com.wireguardui.wireguard_ui_client')"

  warn "Fingerprint SHA256 del APK (release): obtenelo con el signing report de Gradle o keytool."
  echo "  Ej.: keytool -list -v -keystore tu.keystore -alias upload | grep 'SHA256'"
  if yes_no "¿Pegar el fingerprint ahora (se guarda en $ANDROID_SHA_FILE)?" "y"; then
    read -r -p "Pegá el SHA-256 (con o sin dos puntos): " ANDROID_SHA_VAL || true
    ANDROID_SHA_VAL="$(trim "$ANDROID_SHA_VAL")"
    if [[ -n "$ANDROID_SHA_VAL" ]]; then
      umask 077
      printf '%s\n' "$ANDROID_SHA_VAL" >"$ANDROID_SHA_FILE"
      chown "$APP_USER:$APP_GROUP" "$ANDROID_SHA_FILE"
      chmod 600 "$ANDROID_SHA_FILE"
      umask 022
      info "Guardado $ANDROID_SHA_FILE"
    fi
  else
    warn "Después copiá el contenido en $ANDROID_SHA_FILE y restringí permisos (600)."
  fi
fi

FCM_PATH=""
if yes_no "¿Instalar credenciales Firebase (FCM) para push al cliente Android?" "n"; then
  FCM_SRC="$(prompt 'Ruta al JSON de cuenta de servicio en ESTA máquina (se copia a $WG_HOME)' '')"
  [[ -n "$FCM_SRC" ]] || die "Ruta FCM vacía."
  [[ -f "$FCM_SRC" ]] || die "No existe el archivo: $FCM_SRC"
  FCM_PATH="$WG_HOME/firebase-service-account.json"
  install -Dm600 -o "$APP_USER" -g "$APP_GROUP" "$FCM_SRC" "$FCM_PATH"
  info "FCM en $FCM_PATH"
fi

ENV_FILE="$WG_HOME/wireguard-ui.env"
if [[ -f "$ENV_FILE" ]] && ! yes_no "Sobrescribir $ENV_FILE ?" "n"; then
  ENV_FILE_BAK="$WG_HOME/wireguard-ui.env.bak.$(date +%Y%m%d%H%M%S)"
  cp -a "$ENV_FILE" "$ENV_FILE_BAK"
  info "Backup: $ENV_FILE_BAK"
fi

{
  echo "# Generado por setup-linux-production.sh — no commitear"
  echo "BIND_ADDRESS=$BIND_LOOPBACK"
  echo "BASE_PATH=$BASE_PATH_NORM"
  echo "WGUI_ALLOW_WG_QUICK=$WGUI_ALLOW_WG_QUICK"
  echo "WGUI_WG_SYNCCONF_AFTER_APPLY=$WGUI_SYNCCONF"
  echo "SESSION_SECRET_FILE=$SESSION_FILE"
  if [[ -n "$LOG_TAIL" ]]; then
    echo "WGUI_LOG_TAIL_PATH=$LOG_TAIL"
  fi
  if [[ "$PASSKEY_SETUP" == "true" ]]; then
    echo "WGUI_WEBAUTHN_RP_ID=$WEBAUTH_RP_ID"
    echo "WGUI_WEBAUTHN_RP_ORIGINS=$WEBAUTH_ORIGINS"
    echo "WGUI_WEBAUTHN_RP_DISPLAY_NAME=$WEBAUTH_DISP"
    if [[ -f "$ANDROID_SHA_FILE" ]]; then
      echo "WGUI_ANDROID_PASSKEY_SHA256=$ANDROID_SHA_FILE"
    fi
    if [[ -n "$ANDROID_PKG" ]]; then
      echo "WGUI_ANDROID_PASSKEY_PACKAGE=$ANDROID_PKG"
    fi
  fi
  if [[ -n "$FCM_PATH" ]]; then
    echo "FCM_CREDENTIALS_FILE=$FCM_PATH"
  fi
} >"$ENV_FILE.tmp"
install -Dm600 -o "$APP_USER" -g "$APP_GROUP" "$ENV_FILE.tmp" "$ENV_FILE"
rm -f "$ENV_FILE.tmp"
info "Variables de entorno: $ENV_FILE"

info "--- Servicio systemd (arranque automático) ---"
UNIT_PATH="/etc/systemd/system/wireguard-ui.service"
cat >"$UNIT_PATH.tmp" <<UNIT
[Unit]
Description=WireGuard UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$DATA_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_DST
Restart=on-failure
RestartSec=5
# Ajustá capabilities si corrés sin root y necesitás wg syncconf:
# AmbientCapabilities=CAP_NET_ADMIN
# CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
UNIT
install -Dm644 "$UNIT_PATH.tmp" "$UNIT_PATH"
rm -f "$UNIT_PATH.tmp"
info "Unidad systemd: $UNIT_PATH"

systemctl daemon-reload
if yes_no "¿Habilitar wireguard-ui al arranque del sistema e iniciarlo ahora? (systemctl enable --now)" "y"; then
  systemctl enable --now wireguard-ui.service
  systemctl --no-pager -l status wireguard-ui.service || true
  info "Servicio habilitado: arranca solo tras reinicios (WantedBy=multi-user.target)."
else
  warn "Para arranque automático más tarde: systemctl enable --now wireguard-ui"
fi

# --- Caddy opcional --------------------------------------------------------
if yes_no "¿Instalar y configurar Caddy para HTTPS (Let's Encrypt)?" "n"; then
  DOMAIN="$(prompt 'Nombre DNS público que apunta a este servidor (ej. vpn.example.net)' '')"
  [[ -n "$DOMAIN" ]] || die "Dominio vacío."
  ACME_EMAIL="$(prompt "Email para Let's Encrypt (ACME)" 'admin@example.com')"

  if [[ "$DISTRO_DEBIANLIKE" -eq 1 ]]; then
    if ! ensure_caddy_apt_pkg && ! command -v caddy >/dev/null 2>&1; then
      warn "Caddy sigue ausente tras intentar instalación Debian/Ubuntu; instalalo a mano o repetí los pasos Cloudsmith desde la documentación de Caddy."
    fi
  else
    warn "Instalá Caddy manualmente; se generará solo el fragmento de sitio."
  fi

  BACKEND="http://$BIND_LOOPBACK"
  # Si BIND es 0.0.0.0:5000, Caddy debe hablar a 127.0.0.1
  BACKEND="${BACKEND/0.0.0.0/127.0.0.1}"

  CADDY_FRAG="$WG_HOME/caddy-wireguard-ui.caddy"
  cat >"$CADDY_FRAG" <<CADDY
# Fragmento generado — importar desde /etc/caddy/Caddyfile (ver abajo)
$DOMAIN {
  encode zstd gzip
  tls $ACME_EMAIL
  reverse_proxy $BACKEND
}
CADDY
  chmod 644 "$CADDY_FRAG"
  info "Fragmento Caddy escrito: $CADDY_FRAG"

  MAIN_CF="/etc/caddy/Caddyfile"
  MARK_BEGIN="# --- wireguard-ui-installer BEGIN ---"
  MARK_END="# --- wireguard-ui-installer END ---"
  if [[ -f "$MAIN_CF" ]] && grep -qF "$MARK_BEGIN" "$MAIN_CF" 2>/dev/null; then
    warn "Tu Caddyfile ya contiene el bloque del instalador; no lo dupliqué."
  else
    if [[ -f "$MAIN_CF" ]]; then
      {
        echo ""
        echo "$MARK_BEGIN"
        echo "import $CADDY_FRAG"
        echo "$MARK_END"
      } >>"$MAIN_CF"
      info "Añadí 'import $CADDY_FRAG' al final de $MAIN_CF"
    else
      warn "No existe $MAIN_CF. Creá uno mínimo con:"
      echo "   import $CADDY_FRAG"
    fi
  fi

  if command -v caddy >/dev/null 2>&1; then
    if caddy validate --config "$MAIN_CF" 2>/dev/null; then
      if yes_no "¿Recargar Caddy ahora (systemctl reload caddy)?" "y"; then
        systemctl enable caddy 2>/dev/null || true
        systemctl reload caddy || systemctl restart caddy
      fi
    else
      warn "Revisá la sintaxis: caddy validate --config $MAIN_CF"
    fi
  fi

  info "Abrí https://$DOMAIN${BASE_PATH_NORM}/ (BASE_PATH sin doble barra)."
  warn "Passkeys: publicá assetlinks en la raíz HTTPS del host (ver README) además del panel bajo BASE_PATH."
fi

echo
info "Listo. Resumen:"
echo "  Binario:     $BIN_DST"
echo "  Entorno:     $ENV_FILE"
echo "  Servicio:    systemctl status wireguard-ui"
echo "  Datos (db):   $DATA_DIR"
echo "  Panel (local): revisá BIND_ADDRESS y BASE_PATH en $ENV_FILE"
echo
warn "Seguridad: restringí permisos en $WG_HOME, rotá secretos si filtraron, y usá firewall solo donde corresponda."
