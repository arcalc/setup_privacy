#!/usr/bin/env bash
# =============================================================================
# Security DNS - Linux installer
# Repository : https://github.com/arcalc/setup_privacy
# License    : MIT
#
# Installs SpoofDPI as a systemd service, configures DNS-over-TLS through
# systemd-resolved, and points the system and desktop proxy at the local
# SpoofDPI instance. Every file and setting is backed up before it is changed,
# so --uninstall (or --revert) restores the exact previous state.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/arcalc/setup_privacy/main/install.sh | sudo bash
#   sudo bash install.sh --uninstall
# =============================================================================

set -Eeuo pipefail

readonly REPO_RAW="https://raw.githubusercontent.com/arcalc/setup_privacy/main"
readonly SPOOFDPI_REPO="xvzc/SpoofDPI"
readonly SERVICE_NAME="security-dns"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly INSTALL_BIN="/usr/local/bin/spoofdpi"
readonly STATE_DIR="/var/lib/security-dns"
readonly BACKUP_DIR="${STATE_DIR}/backup"
readonly RESOLVED_CONF="/etc/systemd/resolved.conf"
readonly RESOLV_CONF="/etc/resolv.conf"
readonly STUB_RESOLV="/run/systemd/resolve/stub-resolv.conf"
readonly ENV_FILE="/etc/environment"
readonly PORT_CANDIDATES=(8080 8081)

# Optional extra SpoofDPI flags, for example:
#   sudo -E SPOOFDPI_EXTRA_FLAGS="--some-flag value" bash install.sh
SPOOFDPI_EXTRA_FLAGS="${SPOOFDPI_EXTRA_FLAGS:-}"

PORT=""
RELEASE_TAG=""
ASSET_URL=""
SUMS_URL=""
TMP_DIR=""

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }

cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
  return 0
}

on_error() {
  warn "Installation stopped at line $1. Changes made so far are backed up."
  warn "Run 'sudo bash install.sh --uninstall' to revert them."
}

trap cleanup EXIT
trap 'on_error $LINENO' ERR

# -----------------------------------------------------------------------------
# Argument handling
# -----------------------------------------------------------------------------
usage() {
  cat <<EOF
Security DNS - Linux installer

Usage:
  sudo bash install.sh              Install and configure Security DNS
  sudo bash install.sh --uninstall  Revert all changes (alias: --revert)
  bash install.sh --help            Show this help
EOF
}

run_uninstaller() {
  # Prefer a local uninstall.sh when this script runs from a checkout.
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    local dir
    dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${dir}/uninstall.sh" ]]; then
      exec bash "${dir}/uninstall.sh"
    fi
  fi
  local tmp
  tmp="$(mktemp)"
  curl -fsSL -o "$tmp" "${REPO_RAW}/uninstall.sh" || die "Could not download uninstall.sh."
  exec bash "$tmp"
}

# -----------------------------------------------------------------------------
# Preflight checks
# -----------------------------------------------------------------------------
require_root() {
  [[ "${EUID}" -eq 0 ]] || die "This script must be run as root. Use: sudo bash install.sh"
}

check_platform() {
  [[ "$(uname -s)" == "Linux" ]] || die "This installer supports Linux only."
  [[ "$(uname -m)" == "x86_64" ]] || die "Only x86_64 (amd64) is supported. Detected: $(uname -m)."
  [[ -d /run/systemd/system ]] || die "systemd is required but was not detected."
}

install_dependencies() {
  local missing=0 cmd
  for cmd in curl wget tar ss; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      warn "Missing tool: ${cmd}"
      missing=1
    fi
  done

  if [[ "$missing" -eq 1 ]]; then
    log "Installing missing dependencies..."
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl wget tar iproute2
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y -q ca-certificates curl wget tar iproute
    elif command -v pacman >/dev/null 2>&1; then
      pacman -Sy --needed --noconfirm ca-certificates curl wget tar iproute2
    elif command -v zypper >/dev/null 2>&1; then
      zypper --non-interactive install ca-certificates curl wget tar iproute2
    else
      die "No supported package manager found. Install curl, wget, tar, and iproute2 manually."
    fi
  else
    log "All required tools are present."
  fi

  for cmd in curl wget tar ss; do
    command -v "$cmd" >/dev/null 2>&1 || die "Dependency still missing after installation: ${cmd}"
  done

  command -v resolvectl >/dev/null 2>&1 \
    || die "systemd-resolved is required. Install the 'systemd-resolved' package for your distribution."
}

# -----------------------------------------------------------------------------
# Backup helpers
# Each original is recorded once. Re-running the installer never overwrites
# the pre-install snapshot.
# -----------------------------------------------------------------------------
snapshot_file() {  # <path> <key>
  local path="$1" key="$2" base="${BACKUP_DIR}/$2"
  if [[ -e "${base}.file" || -e "${base}.link" || -e "${base}.absent" ]]; then
    log "Backup '${key}' already exists; keeping the original."
    return 0
  fi
  if [[ -L "$path" ]]; then
    readlink "$path" > "${base}.link"
  elif [[ -f "$path" ]]; then
    cp -a "$path" "${base}.file"
  else
    : > "${base}.absent"
  fi
  log "Backed up ${path}"
}

has_user_bus() {  # <user>
  [[ -S "/run/user/$(id -u "$1")/bus" ]]
}

user_gsettings() {  # <user> <gsettings arguments...>
  local user="$1"; shift
  local bus="/run/user/$(id -u "$user")/bus"
  [[ -S "$bus" ]] || return 1
  runuser -u "$user" -- env DBUS_SESSION_BUS_ADDRESS="unix:path=${bus}" gsettings "$@" </dev/null
}

readonly GNOME_KEYS=(
  "org.gnome.system.proxy mode"
  "org.gnome.system.proxy autoconfig-url"
  "org.gnome.system.proxy ignore-hosts"
  "org.gnome.system.proxy.http host"
  "org.gnome.system.proxy.http port"
  "org.gnome.system.proxy.https host"
  "org.gnome.system.proxy.https port"
)

snapshot_gnome() {  # <user>
  local user="$1" out="${BACKUP_DIR}/gnome-${1}.tsv" entry schema key value
  [[ -e "$out" ]] && return 0
  : > "$out"
  for entry in "${GNOME_KEYS[@]}"; do
    schema="${entry% *}"
    key="${entry##* }"
    value="$(user_gsettings "$user" get "$schema" "$key" 2>/dev/null || true)"
    printf '%s\t%s\t%s\n' "$schema" "$key" "$value" >> "$out"
  done
  log "Backed up GNOME proxy settings for ${user}"
}

backup_state() {
  mkdir -p "$BACKUP_DIR"
  chmod 0700 "$STATE_DIR"

  snapshot_file "$RESOLVED_CONF" resolved.conf
  snapshot_file "$RESOLV_CONF" resolv.conf
  snapshot_file "$ENV_FILE" environment

  # Desktop users: UID 1000 to 65533 with a home directory under /home.
  if [[ ! -f "${BACKUP_DIR}/users.tsv" ]]; then
    awk -F: '$3 >= 1000 && $3 < 65534 && $6 ~ /^\/home\// {printf "%s\t%s\n", $1, $6}' /etc/passwd \
      > "${BACKUP_DIR}/users.tsv"
  fi

  local user home
  while IFS=$'\t' read -r user home; do
    [[ -n "$user" ]] || continue
    if has_user_bus "$user" && command -v gsettings >/dev/null 2>&1; then
      snapshot_gnome "$user"
    fi
    if command -v kwriteconfig6 >/dev/null 2>&1 || command -v kwriteconfig5 >/dev/null 2>&1; then
      snapshot_file "${home}/.config/kioslaverc" "kde-${user}"
    fi
  done < "${BACKUP_DIR}/users.tsv"
}

# -----------------------------------------------------------------------------
# Port selection
# -----------------------------------------------------------------------------
port_in_use() {  # <port>
  [[ -n "$(ss -H -ltn "sport = :$1" 2>/dev/null)" ]]
}

select_port() {
  local p
  for p in "${PORT_CANDIDATES[@]}"; do
    if port_in_use "$p"; then
      warn "Port ${p} is already in use."
    else
      printf '%s' "$p"
      return 0
    fi
  done
  die "Neither port 8080 nor 8081 is free. Free one of them and run the installer again."
}

# -----------------------------------------------------------------------------
# SpoofDPI download
# -----------------------------------------------------------------------------
resolve_release() {
  local api="https://api.github.com/repos/${SPOOFDPI_REPO}/releases/latest"
  local json urls
  local -a auth=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi

  json="$(curl -fsSL --retry 3 -H 'Accept: application/vnd.github+json' "${auth[@]}" "$api")" \
    || die "Could not query the GitHub API for ${SPOOFDPI_REPO} (network issue or rate limit)."

  RELEASE_TAG="$(printf '%s' "$json" | grep -o '"tag_name": *"[^"]*"' | head -n1 \
    | sed 's/.*"\([^"]*\)"$/\1/' || true)"
  urls="$(printf '%s' "$json" | grep -o '"browser_download_url": *"[^"]*"' \
    | sed 's/.*"\(https[^"]*\)"$/\1/' || true)"

  ASSET_URL="$(printf '%s\n' "$urls" | grep -iE 'linux' | grep -iE 'amd64|x86_64' \
    | grep -viE '\.(sha256|sig|asc|txt|md5)$' | head -n1 || true)"
  SUMS_URL="$(printf '%s\n' "$urls" | grep -iE 'sha256|checksum' | grep -viE 'windows|darwin|arm' \
    | head -n1 || true)"

  [[ -n "$ASSET_URL" ]] || die "No linux-amd64 asset found in SpoofDPI release ${RELEASE_TAG:-unknown}."
  log "Latest SpoofDPI release: ${RELEASE_TAG}"
}

verify_checksum() {  # <file> <sums file> <asset name>
  local file="$1" sums="$2" name="$3" expected actual
  expected="$(awk -v n="$name" 'index($0, n) {print $1; exit}' "$sums" || true)"
  if [[ -z "$expected" ]]; then
    expected="$(awk 'NF {print $1; exit}' "$sums" || true)"
  fi
  expected="$(printf '%s' "$expected" | tr -d '[:space:]')"
  if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
    warn "Checksum file could not be parsed; skipping verification."
    return 0
  fi
  actual="$(sha256sum "$file" | awk '{print $1}')"
  [[ "${expected,,}" == "${actual,,}" ]] || die "SHA-256 mismatch for ${name}. Refusing to install."
  log "SHA-256 checksum verified."
}

download_binary() {
  TMP_DIR="$(mktemp -d)"
  local name file bin=""
  name="$(basename "$ASSET_URL")"
  file="${TMP_DIR}/${name}"

  log "Downloading ${name}"
  curl -fL --retry 3 -o "$file" "$ASSET_URL" || die "Download failed: ${ASSET_URL}"

  if [[ -n "$SUMS_URL" ]] && curl -fsSL -o "${TMP_DIR}/checksums" "$SUMS_URL"; then
    verify_checksum "$file" "${TMP_DIR}/checksums" "$name"
  else
    warn "No checksum published for this release; integrity was not verified."
  fi

  case "$name" in
    *.tar.gz|*.tgz)
      mkdir -p "${TMP_DIR}/extract"
      tar -xzf "$file" -C "${TMP_DIR}/extract"
      bin="$(find "${TMP_DIR}/extract" -type f -iname 'spoofdpi*' ! -name '*.sha256' | head -n1 || true)"
      ;;
    *)
      bin="$file"
      ;;
  esac

  [[ -n "$bin" && -f "$bin" ]] || die "Could not locate the SpoofDPI binary inside ${name}."
  install -m 0755 "$bin" "$INSTALL_BIN"
  log "Installed ${INSTALL_BIN} (${RELEASE_TAG})"
}

# -----------------------------------------------------------------------------
# systemd service
# -----------------------------------------------------------------------------
write_service() {
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Security DNS - SpoofDPI local DPI-bypass proxy
Documentation=https://github.com/arcalc/setup_privacy
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_BIN} --listen-addr 127.0.0.1:${PORT} ${SPOOFDPI_EXTRA_FLAGS}
Restart=on-failure
RestartSec=5
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$SERVICE_FILE"
  log "Created ${SERVICE_FILE}"
}

# -----------------------------------------------------------------------------
# DNS-over-TLS
# -----------------------------------------------------------------------------
configure_dot() {
  systemctl enable --now systemd-resolved >/dev/null 2>&1 \
    || die "Could not enable systemd-resolved."

  cat > "$RESOLVED_CONF" <<EOF
# Managed by Security DNS. The original file is restored on uninstall.
[Resolve]
DNS=1.1.1.1 1.0.0.1
FallbackDNS=
DNSOverTLS=yes
DNSSEC=allow-downgrade
Domains=~.
EOF
  log "Wrote DNS-over-TLS configuration to ${RESOLVED_CONF}"

  [[ -f "$STUB_RESOLV" ]] || die "systemd-resolved stub file not found at ${STUB_RESOLV}."
  ln -sf "$STUB_RESOLV" "$RESOLV_CONF"
  systemctl restart systemd-resolved

  if resolvectl query one.one.one.one >/dev/null 2>&1; then
    log "DNS resolution works through 1.1.1.1 / 1.0.0.1."
  else
    warn "Test DNS query failed. Inspect with: resolvectl status"
  fi
}

# -----------------------------------------------------------------------------
# System and desktop proxy
# -----------------------------------------------------------------------------
apply_env() {  # <port>
  local port="$1" tmp
  tmp="$(mktemp)"
  if [[ -f "$ENV_FILE" ]]; then
    sed '/^# BEGIN security-dns$/,/^# END security-dns$/d' "$ENV_FILE" > "$tmp"
  else
    : > "$tmp"
  fi
  {
    cat "$tmp"
    echo "# BEGIN security-dns"
    echo "# Managed by Security DNS. Restored on uninstall."
    echo "http_proxy=http://127.0.0.1:${port}"
    echo "https_proxy=http://127.0.0.1:${port}"
    echo "HTTP_PROXY=http://127.0.0.1:${port}"
    echo "HTTPS_PROXY=http://127.0.0.1:${port}"
    echo "no_proxy=localhost,127.0.0.1,::1"
    echo "NO_PROXY=localhost,127.0.0.1,::1"
    echo "# END security-dns"
  } > "${tmp}.new"
  cat "${tmp}.new" > "$ENV_FILE"
  rm -f "$tmp" "${tmp}.new"
  log "Proxy environment variables written to ${ENV_FILE}"
}

apply_gnome() {  # <user> <port>
  local user="$1" port="$2"
  if user_gsettings "$user" set org.gnome.system.proxy mode 'manual' \
    && user_gsettings "$user" set org.gnome.system.proxy.http host '127.0.0.1' \
    && user_gsettings "$user" set org.gnome.system.proxy.http port "$port" \
    && user_gsettings "$user" set org.gnome.system.proxy.https host '127.0.0.1' \
    && user_gsettings "$user" set org.gnome.system.proxy.https port "$port" \
    && user_gsettings "$user" set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']"; then
    log "GNOME proxy configured for ${user}"
  else
    warn "Could not configure GNOME proxy for ${user}."
  fi
  return 0
}

apply_kde() {  # <user> <port>
  local user="$1" port="$2" kw
  kw="$(command -v kwriteconfig6 2>/dev/null || command -v kwriteconfig5 2>/dev/null || true)"
  [[ -n "$kw" ]] || return 0
  kde_set() {  # <key> <value>
    runuser -u "$user" -- "$kw" --file kioslaverc --group "Proxy Settings" --key "$1" "$2" </dev/null
  }
  if kde_set ProxyType 1 \
    && kde_set httpProxy "http://127.0.0.1:${port}" \
    && kde_set httpsProxy "http://127.0.0.1:${port}" \
    && kde_set NoProxyFor "localhost,127.0.0.0/8,::1"; then
    log "KDE proxy configured for ${user}"
  else
    warn "Could not configure KDE proxy for ${user}."
  fi
  return 0
}

configure_proxy() {
  apply_env "$PORT"

  local user home
  while IFS=$'\t' read -r user home; do
    [[ -n "$user" ]] || continue
    if has_user_bus "$user" && command -v gsettings >/dev/null 2>&1; then
      apply_gnome "$user" "$PORT"
    fi
    apply_kde "$user" "$PORT"
  done < "${BACKUP_DIR}/users.tsv"
}

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print_summary() {
  cat <<EOF

$(printf '\033[1;32m')Security DNS installed successfully.$(printf '\033[0m')

  Local proxy : 127.0.0.1:${PORT} (service: ${SERVICE_NAME}, starts on boot)
  DNS         : DNS-over-TLS via 1.1.1.1 / 1.0.0.1, no plaintext fallback
  Proxy       : environment variables, plus GNOME/KDE where detected

Next steps:
  1. Log out and back in so the proxy variables apply to all applications.
  2. Restart your browsers completely.
  3. Enable ECH and disable QUIC/HTTP3 in your browser (see README.md).
  4. On other window managers, set the proxy manually: 127.0.0.1:${PORT}.

Important limits:
  - Your ISP can still see destination IP addresses and traffic volume.
  - Apps that ignore the system proxy, and browsers using QUIC, may bypass the proxy.

Revert everything with:
  curl -fsSL ${REPO_RAW}/install.sh | sudo bash -s -- --uninstall

EOF
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main_install() {
  require_root
  check_platform

  step "Checking dependencies"
  install_dependencies

  step "Backing up current DNS and proxy configuration"
  backup_state

  step "Stopping any previous instance"
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true

  step "Selecting a local port"
  PORT="$(select_port)"
  log "SpoofDPI will listen on 127.0.0.1:${PORT}"

  step "Downloading SpoofDPI"
  resolve_release
  download_binary

  step "Creating the ${SERVICE_NAME} service"
  write_service
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  sleep 2
  port_in_use "$PORT" \
    || die "SpoofDPI is not listening on 127.0.0.1:${PORT}. Check: journalctl -u ${SERVICE_NAME} -n 50"
  printf '%s\n' "$PORT" > "${STATE_DIR}/port"
  log "Service is running"

  step "Enabling DNS-over-TLS"
  configure_dot

  step "Configuring the system proxy"
  configure_proxy

  print_summary
}

case "${1:-}" in
  --uninstall|--revert)
    require_root
    run_uninstaller
    ;;
  -h|--help)
    usage
    ;;
  "")
    main_install
    ;;
  *)
    usage >&2
    die "Unknown option: $1"
    ;;
esac
