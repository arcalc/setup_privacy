#!/usr/bin/env bash
# =============================================================================
# Security DNS - Linux uninstaller
# Repository : https://github.com/arcalc/setup_privacy
# License    : MIT
#
# Two modes:
#   --restore-only  Reverts network, DNS, and proxy settings to the original
#                   backups and stops all tunnels. The application, the
#                   dependencies, the shortcuts, and the backups stay in place.
#   (default)       Full uninstall. Reverts the same settings, removes WARP and
#                   WireGuard only if this tool installed them, removes the
#                   service, binary, menu, and desktop entry, and deletes the
#                   backups once everything is restored.
#
# Usage:
#   sudo bash uninstall.sh                 full uninstall
#   sudo bash uninstall.sh --restore-only  restore original settings only
#   sudo bash uninstall.sh --tool NAME     remove one tool: spoofdpi, warp or wireguard
# =============================================================================

set -Eeuo pipefail

readonly SERVICE_NAME="security-dns"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly WG_SERVICE="wg-quick@security-dns"
readonly WG_CONF="/etc/wireguard/security-dns.conf"
readonly WGCF_BIN="/usr/local/bin/wgcf"
readonly SPOOF_BIN="/usr/local/bin/spoofdpi"
readonly APP_BIN="/usr/local/bin/security-dns"
readonly LIB_DIR="/usr/local/lib/security-dns"
readonly DESKTOP_FILE="/usr/share/applications/security-dns.desktop"
readonly STATE_DIR="/var/lib/security-dns"
readonly STATE_FILE="${STATE_DIR}/state.env"
readonly BACKUP_DIR="${STATE_DIR}/backup"
readonly USERS_FILE="${BACKUP_DIR}/users.tsv"
readonly RESOLVED_CONF="/etc/systemd/resolved.conf"
readonly RESOLV_CONF="/etc/resolv.conf"
readonly ENV_FILE="/etc/environment"
readonly WARP_APT_LIST="/etc/apt/sources.list.d/cloudflare-client.list"
readonly WARP_APT_KEY="/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
readonly WARP_DNF_REPO="/etc/yum.repos.d/cloudflare-warp.repo"

RESTORE_ONLY=0
TOOL_ONLY=""
readonly SPOOF_CONFIG="/usr/local/lib/security-dns/spoofdpi.toml"
readonly WGCF_DIR="/var/lib/security-dns/wgcf"
PENDING=0
PM=""

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }

on_error() {
  warn "Stopped at line $1. Backups were kept so you can run it again."
}
trap 'on_error $LINENO' ERR

# -----------------------------------------------------------------------------
# State file helpers (KEY=VALUE, written by install.sh)
# -----------------------------------------------------------------------------
state_value() {  # <key>
  if [[ -f "$STATE_FILE" ]]; then
    sed -n "s/^${1}=//p" "$STATE_FILE" | tail -n1
  fi
  return 0
}

state_set() {  # <key> <value>
  mkdir -p "$STATE_DIR"
  touch "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
  sed -i "/^${1}=/d" "$STATE_FILE"
  printf '%s=%s\n' "$1" "$2" >> "$STATE_FILE"
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then PM="apt"
  elif command -v dnf >/dev/null 2>&1; then PM="dnf"
  else PM=""
  fi
}

user_gsettings() {  # <user> <gsettings arguments...>
  local user="$1"; shift
  local bus="/run/user/$(id -u "$user")/bus"
  [[ -S "$bus" ]] || return 1
  runuser -u "$user" -- env DBUS_SESSION_BUS_ADDRESS="unix:path=${bus}" gsettings "$@" </dev/null
}

# Restores one file from its backup. Does nothing when no backup exists.
restore_file() {  # <path> <key> [owner]
  local path="$1" key="$2" owner="${3:-}" base="${BACKUP_DIR}/$2"
  if [[ -f "${base}.file" ]]; then
    rm -f "$path"
    cp -a "${base}.file" "$path"
  elif [[ -f "${base}.link" ]]; then
    rm -f "$path"
    ln -s "$(cat "${base}.link")" "$path"
  elif [[ -f "${base}.absent" ]]; then
    rm -f "$path"
  else
    return 0
  fi
  if [[ -n "$owner" ]]; then
    chown "$owner" "$path"
  fi
  log "Restored ${path}"
}

# Restores GNOME proxy keys. Returns 1 when the user session is unavailable.
restore_gnome() {  # <user>
  local user="$1" file="${BACKUP_DIR}/gnome-${1}.tsv" schema key value
  [[ -f "$file" ]] || return 0
  if [[ ! -S "/run/user/$(id -u "$user")/bus" ]]; then
    warn "GNOME settings for ${user} need an active session; log in as ${user} and run this again."
    return 1
  fi
  while IFS=$'\t' read -r schema key value; do
    [[ -n "$value" ]] || continue
    user_gsettings "$user" set "$schema" "$key" "$value" \
      || warn "Could not restore ${schema} ${key} for ${user}."
  done < "$file"
  log "GNOME proxy settings restored for ${user}"
}

# -----------------------------------------------------------------------------
# Steps shared by both modes
# -----------------------------------------------------------------------------
stop_services() {
  step "Stopping tunnels and the proxy"
  systemctl disable --now "$WG_SERVICE" >/dev/null 2>&1 || true
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
  log "Proxy and WireGuard services stopped"
}

disconnect_warp() {
  if ! command -v warp-cli >/dev/null 2>&1; then
    return 0
  fi
  warp-cli --accept-tos disconnect >/dev/null 2>&1 || true
  if [[ "$(state_value WARP_SVC_ENABLED_BY_US)" == "1" ]]; then
    systemctl disable --now warp-svc >/dev/null 2>&1 || true
  fi
  log "Cloudflare WARP disconnected"
}

restore_network_settings() {
  step "Restoring network, DNS, and proxy settings"
  if [[ ! -d "$BACKUP_DIR" ]]; then
    warn "No backup directory found at ${BACKUP_DIR}. Network settings cannot be restored automatically."
    return 0
  fi

  restore_file "$ENV_FILE" environment

  if [[ -f "$USERS_FILE" ]]; then
    local user home
    while IFS=$'\t' read -r user home; do
      [[ -n "$user" ]] || continue
      restore_gnome "$user" || PENDING=1
      restore_file "${home}/.config/kioslaverc" "kde-${user}" "${user}:"
    done < "$USERS_FILE"
  fi

  restore_file "$RESOLVED_CONF" resolved.conf
  restore_file "$RESOLV_CONF" resolv.conf
  systemctl restart systemd-resolved 2>/dev/null || warn "Could not restart systemd-resolved."
}

# -----------------------------------------------------------------------------
# Restore-only mode
# -----------------------------------------------------------------------------
run_restore_only() {
  if [[ "$(state_value INSTALLED)" != "1" && ! -d "$BACKUP_DIR" ]]; then
    die "Security DNS has no recorded backups to restore. Nothing was changed."
  fi

  stop_services
  disconnect_warp

  if [[ -f "$WG_CONF" && "$(state_value WG_CONF_ADDED)" == "1" ]]; then
    rm -f "$WG_CONF"
    log "Removed the WireGuard tunnel profile"
  fi

  restore_network_settings

  state_set MODE R
  state_set DNS_RESTORED 1

  if [[ "$PENDING" -eq 1 ]]; then
    warn "Some desktop settings were not restored because a user is not logged in. Run this again after that user logs in."
  fi
  log "Original settings restored. The app, dependencies, and shortcuts are still installed."
}

# -----------------------------------------------------------------------------
# Full uninstall
# -----------------------------------------------------------------------------
remove_warp() {
  if [[ "$(state_value WARP_PKG_ADDED)" != "1" && "$(state_value WARP_REGISTERED_BY_US)" != "1" \
        && "$(state_value WARP_REPO_ADDED)" != "1" && "$(state_value WARP_KEY_ADDED)" != "1" \
        && "$(state_value WARP_SVC_ENABLED_BY_US)" != "1" ]]; then
    return 0
  fi

  step "Reverting Cloudflare WARP"
  if command -v warp-cli >/dev/null 2>&1; then
    if [[ "$(state_value WARP_REGISTERED_BY_US)" == "1" ]]; then
      warp-cli --accept-tos registration delete >/dev/null 2>&1 || warn "Could not delete the WARP registration."
    fi
    warp-cli --accept-tos disconnect >/dev/null 2>&1 || true
  fi

  if [[ "$(state_value WARP_SVC_ENABLED_BY_US)" == "1" ]]; then
    systemctl disable --now warp-svc >/dev/null 2>&1 || true
  fi

  if [[ "$(state_value WARP_PKG_ADDED)" == "1" ]]; then
    case "$PM" in
      apt) DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq cloudflare-warp >/dev/null 2>&1 \
             || warn "Could not remove the cloudflare-warp package." ;;
      dnf) dnf remove -y -q cloudflare-warp >/dev/null 2>&1 \
             || warn "Could not remove the cloudflare-warp package." ;;
    esac
  fi

  if [[ "$(state_value WARP_REPO_ADDED)" == "1" ]]; then
    rm -f "$WARP_APT_LIST" "$WARP_DNF_REPO"
  fi
  if [[ "$(state_value WARP_KEY_ADDED)" == "1" ]]; then
    rm -f "$WARP_APT_KEY"
  fi
  log "Cloudflare WARP changes reverted"
}

remove_wireguard() {
  if [[ -f "$WG_CONF" && "$(state_value WG_CONF_ADDED)" == "1" ]]; then
    rm -f "$WG_CONF"
    log "Removed ${WG_CONF}"
  fi

  if [[ "$(state_value WG_TOOLS_ADDED)" == "1" ]]; then
    case "$PM" in
      apt) DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq wireguard-tools >/dev/null 2>&1 \
             || warn "Could not remove wireguard-tools." ;;
      dnf) dnf remove -y -q wireguard-tools >/dev/null 2>&1 \
             || warn "Could not remove wireguard-tools." ;;
    esac
    log "Removed wireguard-tools (added by Security DNS)"
  fi

  if [[ "$(state_value WGCF_BIN_ADDED)" == "1" ]]; then
    rm -f "$WGCF_BIN"
    log "Removed wgcf"
  fi
}

remove_files() {
  step "Removing Security DNS files"
  rm -f "$SPOOF_BIN"
  rm -f "$DESKTOP_FILE"
  rm -rf "$LIB_DIR"
  rm -f "$APP_BIN"
  log "SpoofDPI binary, menu, and desktop entry removed"
}

run_full_uninstall() {
  if [[ ! -d "$STATE_DIR" ]]; then
    warn "No Security DNS state found at ${STATE_DIR}. Removing any remaining application files."
  fi

  stop_services
  remove_warp
  remove_wireguard
  restore_network_settings
  remove_files

  if [[ "$PENDING" -eq 1 ]]; then
    warn "Some desktop settings could not be restored yet. Backups were kept in ${STATE_DIR}."
    warn "Log in as the affected user and run: sudo bash uninstall.sh"
    return 0
  fi

  rm -rf "$STATE_DIR"
  log "Backups removed. Your system has been returned to its previous state."
  printf '\nOpen a new terminal, or log out and back in, so environment changes take effect.\n'
}


# -----------------------------------------------------------------------------
# Remove a single tool (used by the Advanced Tool Manager's Uninstall action).
# Only things this app installed are removed; anything that was already on the
# system before is left in place.
# -----------------------------------------------------------------------------
state_unset() {  # <key>
  [[ -f "$STATE_FILE" ]] && sed -i "/^${1}=/d" "$STATE_FILE"
  return 0
}

remove_tool_spoofdpi() {
  step "Removing SpoofDPI"
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE" "$SPOOF_CONFIG"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
  if [[ -n "$(state_value SPOOFDPI_TAG)" ]]; then
    rm -f "$SPOOF_BIN"
    state_unset SPOOFDPI_TAG
    log "SpoofDPI program removed"
  else
    log "SpoofDPI program was not installed by Security DNS; it was left in place"
  fi
}

remove_tool_warp() {
  remove_warp
  local key
  for key in WARP_PKG_ADDED WARP_REGISTERED_BY_US WARP_REPO_ADDED WARP_KEY_ADDED WARP_SVC_ENABLED_BY_US; do
    state_unset "$key"
  done
}

remove_tool_wireguard() {
  step "Removing WireGuard"
  systemctl disable --now "$WG_SERVICE" >/dev/null 2>&1 || true
  remove_wireguard
  rm -rf "$WGCF_DIR"
  local key
  for key in WG_CONF_ADDED WG_TOOLS_ADDED WGCF_BIN_ADDED WGCF_TAG; do
    state_unset "$key"
  done
}

run_tool_removal() {
  case "$TOOL_ONLY" in
    spoofdpi)  remove_tool_spoofdpi ;;
    warp)      remove_tool_warp ;;
    wireguard) remove_tool_wireguard ;;
    *) die "Unknown tool: ${TOOL_ONLY} (use spoofdpi, warp or wireguard)" ;;
  esac
  log "Done. Your original network settings are still backed up."
}

main() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash uninstall.sh"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --restore-only) RESTORE_ONLY=1 ;;
      --tool) shift; TOOL_ONLY="${1:-}" ;;
      *) die "Unknown option: ${1}" ;;
    esac
    shift
  done

  detect_package_manager

  if [[ -n "$TOOL_ONLY" ]]; then
    run_tool_removal
  elif [[ "$RESTORE_ONLY" -eq 1 ]]; then
    run_restore_only
  else
    run_full_uninstall
  fi
}

main "$@"
