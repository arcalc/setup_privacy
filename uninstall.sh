#!/usr/bin/env bash
# =============================================================================
# Security DNS - Linux uninstaller
# Repository : https://github.com/arcalc/setup_privacy
# License    : MIT
#
# Restores the exact files and settings captured by install.sh, then removes
# the SpoofDPI service and binary. Safe to run more than once.
#
# Usage:
#   sudo bash uninstall.sh
# =============================================================================

set -Eeuo pipefail

readonly SERVICE_NAME="security-dns"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly INSTALL_BIN="/usr/local/bin/spoofdpi"
readonly STATE_DIR="/var/lib/security-dns"
readonly BACKUP_DIR="${STATE_DIR}/backup"
readonly RESOLVED_CONF="/etc/systemd/resolved.conf"
readonly RESOLV_CONF="/etc/resolv.conf"
readonly ENV_FILE="/etc/environment"

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }

on_error() {
  warn "Uninstall stopped at line $1. Backups were kept so you can run it again."
}
trap 'on_error $LINENO' ERR

[[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash uninstall.sh"

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
    warn "GNOME settings for ${user} need an active session; log in as ${user} and run this uninstaller again."
    return 1
  fi
  while IFS=$'\t' read -r schema key value; do
    [[ -n "$value" ]] || continue
    user_gsettings "$user" set "$schema" "$key" "$value" \
      || warn "Could not restore ${schema} ${key} for ${user}."
  done < "$file"
  log "GNOME proxy settings restored for ${user}"
}

main_uninstall() {
  local pending=0

  if [[ ! -d "$BACKUP_DIR" ]]; then
    warn "No backup directory found at ${BACKUP_DIR}. Only the service and binary will be removed."
  fi

  step "Restoring proxy settings"
  if [[ -d "$BACKUP_DIR" ]]; then
    restore_file "$ENV_FILE" environment

    if [[ -f "${BACKUP_DIR}/users.tsv" ]]; then
      local user home
      while IFS=$'\t' read -r user home; do
        [[ -n "$user" ]] || continue
        restore_gnome "$user" || pending=1
        restore_file "${home}/.config/kioslaverc" "kde-${user}" "${user}:"
      done < "${BACKUP_DIR}/users.tsv"
    fi
  fi

  step "Stopping and removing the service"
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$INSTALL_BIN"
  log "Service and binary removed"

  step "Restoring DNS configuration"
  if [[ -d "$BACKUP_DIR" ]]; then
    restore_file "$RESOLVED_CONF" resolved.conf
    restore_file "$RESOLV_CONF" resolv.conf
    systemctl restart systemd-resolved 2>/dev/null || warn "Could not restart systemd-resolved."
  fi

  if [[ "$pending" -eq 1 ]]; then
    warn "Some desktop settings could not be restored yet. Backups were kept in ${STATE_DIR}."
    warn "Log in as the affected user and run: sudo bash uninstall.sh"
    return 0
  fi

  rm -rf "$STATE_DIR"
  log "Backups removed. Your system has been returned to its previous state."
  printf '\nOpen a new terminal, or log out and back in, so environment changes take effect.\n'
}

main_uninstall
