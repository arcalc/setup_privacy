#!/usr/bin/env bash
# Automated tests for the Linux CLI logic: error classifier, settings validation,
# free-port finder, translations, and the fail -> explain -> fix -> retry loop.
# Nothing here touches your system: state files are redirected to a temp folder.
#
# Run:  bash cli/tests/run.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
REDIRECT="s#/var/lib/security-dns#${WORK}/state#g; s#/usr/local/lib/security-dns#${WORK}/lib#g; s#/etc/systemd/system#${WORK}/unit#g; s#/etc/systemd/resolved.conf.d#${WORK}/resolved.d#g; s#/etc/systemd/resolved.conf#${WORK}/resolved.conf#g; s#/run/systemd/resolve/stub-resolv.conf#${WORK}/stub-resolv.conf#g; s#/etc/resolv.conf#${WORK}/resolv.conf#g; s#/etc/environment#${WORK}/environment#g; s#/etc/wireguard#${WORK}/wireguard#g"
sed "$REDIRECT" "${HERE}/../install.sh" > "${WORK}/install_t.sh"
sed "$REDIRECT" "${HERE}/../uninstall.sh" > "${WORK}/uninstall_t.sh"
export SECURITY_DNS_SOURCE_ONLY=1
source "${WORK}/install_t.sh"
ERR_LOG="$(mktemp)"
pass=0; fail=0
check() { if [[ "$2" == "$3" ]]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $1 -> got '$2' expected '$3'"; fi; }

echo "== classifier"
check "port"      "$(classify_problem 'listen tcp 127.0.0.1:8080: bind: address already in use')" port_in_use
check "flag"      "$(classify_problem 'application failed to start
flag provided but not defined: -addr')" unsupported_flag
check "resolvconf" "$(classify_problem '/usr/bin/wg-quick: line 32: resolvconf: command not found')" missing_resolvconf
check "gpg"       "$(classify_problem 'bash: gpg: command not found')" missing_tool
check "net"       "$(classify_problem 'curl: (6) Could not resolve host: api.github.com')" network
check "rate"      "$(classify_problem 'curl: (22) The requested URL returned error: 403')" ratelimit
check "perm"      "$(classify_problem 'cp: cannot create: Permission denied')" permission
check "resolved"  "$(classify_problem 'resolvectl: command not found')" resolved_missing
check "asset"     "$(classify_problem 'No linux-amd64 asset found in SpoofDPI release v1')" no_asset
check "conflict"  "$(classify_problem 'CONFLICT:warp - WARP is connected')" conflict
check "unknown"   "$(classify_problem 'something odd happened')" unknown
check "busy-warn-not-port" "$(classify_problem 'Port 8080 is taken by another application. Choosing another port.')" unknown
check "toolname"  "$(missing_tool_name 'line 3: gpg: command not found')" gpg
check "toolname2" "$(missing_tool_name 'Missing tool: tar')" tar

echo "== settings"
check "default port" "$(setting_get SPOOF_PORT)" 8080
setting_set SPOOF_PORT 9090; check "set port" "$(setting_get SPOOF_PORT)" 9090
setting_set WG_ENDPOINT ''; check "empty override" "$(setting_get WG_ENDPOINT)" ""
for v in "SPOOF_PORT 8081:0" "SPOOF_PORT 70000:1" "SPOOF_PORT abc:1" "DNS_SERVERS 9.9.9.9 149.112.112.112:0" "DNS_SERVERS 1.1.1.1#cloudflare-dns.com:0" "DNS_SERVERS evil;rm:1" "WG_ENDPOINT engage.cloudflareclient.com:2408:0" "WG_ENDPOINT [2606:4700::1]:2408:0" "WG_ENDPOINT nohostport:1" "WG_STRIP_DNS 2:1" "SPOOF_ARG_STYLE flags:0" "SPOOF_ARG_STYLE bogus:1" "NET_TIMEOUT 4:1" "NET_TIMEOUT 60:0" "SPOOF_EXTRA_FLAGS --foo;ls:1" "SPOOF_EXTRA_FLAGS --foo=bar:0" "SPOOF_PATH /nonexistent:1" "SPOOF_PATH /bin/true:0"; do
  exp="${v##*:}"; body="${v%:*}"; key="${body%% *}"; val="${body#* }"
  if setting_valid "$key" "$val"; then got=0; else got=1; fi
  check "valid $key=$val" "$got" "$exp"
done

echo "== ports"
python3 -c "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',18080)); s.listen(); time.sleep(6)" &
sleep 1
if port_in_use 18080; then got=busy; else got=free; fi; check "busy detected" "$got" busy
check "free port search" "$(find_free_port 18080)" 18081
if port_in_use 18999; then got=busy; else got=free; fi; check "free detected" "$got" free

echo "== i18n"
UI_LANG=ar; check "arabic menu_q" "$(msg menu_q)" "q) خروج"
UI_LANG=en; check "english fmt" "$(msg menu_head 3.0.0)" "Security DNS v3.0.0"
for k in $(printf '%s\n' "${!MSG_EN[@]}" | sort); do [[ -n "${MSG_AR[$k]:-}" ]] || { fail=$((fail+1)); echo "FAIL: missing Arabic for $k"; }; done
for k in $(printf '%s\n' "${!MSG_AR[@]}" | sort); do [[ -n "${MSG_EN[$k]:-}" ]] || { fail=$((fail+1)); echo "FAIL: missing English for $k"; }; done
for k in "${SETTING_KEYS[@]}"; do [[ -n "${MSG_EN[set_$k]:-}" ]] || { fail=$((fail+1)); echo "FAIL: no help for setting $k"; }; done
echo "EN keys: ${#MSG_EN[@]}  AR keys: ${#MSG_AR[@]}"

echo "== recovery loop (simulated failures)"
setting_set SPOOF_PORT 18080
COUNT_FILE=$(mktemp); echo 0 > "$COUNT_FILE"
sim_op() { local n; n=$(cat "$COUNT_FILE"); echo $((n+1)) > "$COUNT_FILE"; local p; p=$(setting_get SPOOF_PORT)
  if port_in_use "$p"; then echo "listen tcp 127.0.0.1:$p: bind: address already in use" >&2; exit 1; fi; echo "started on $p"; }
out="$(printf 'a\n' | guarded sim_op 2>&1)"; rc=$?
check "guarded rc" "$rc" 0
check "port moved" "$(setting_get SPOOF_PORT)" 18081
check "attempts" "$(cat "$COUNT_FILE")" 2
echo "$out" | grep -q "Port is already taken" && echo "  dialog shown: yes" || { fail=$((fail+1)); echo "FAIL: dialog not shown"; }
echo "$out" | grep -q "Apply fix" && echo "  apply-fix prompt: yes" || { fail=$((fail+1)); echo "FAIL: no prompt"; }

echo "== cancel path"
always_fail() { echo "weird failure" >&2; exit 1; }
printf 'x\n' | guarded always_fail >/dev/null 2>&1; check "cancel rc" "$?" 1

echo "== giving up after repeated same problem"
printf 'a\na\na\na\na\n' | guarded always_fail >/dev/null 2>&1; check "giveup rc" "$?" 1

echo "== arabic dialog"
UI_LANG=ar
out="$(printf 'x\n' | guarded always_fail 2>&1)"; echo "$out" | grep -q "خطأ غير متوقع" && echo "  arabic dialog: yes" || { fail=$((fail+1)); echo "FAIL: arabic dialog"; }

# =============================================================================
# Audit regression tests (one group per bug that was found and fixed)
# =============================================================================
UI_LANG=en
RUN_TMP="$(mktemp -d)"
mkdir -p "$(dirname "$SETTINGS_FILE")"; rm -f "$SETTINGS_FILE"

echo "== audit: SpoofDPI flag detection (single-dash and double-dash help styles)"
mkfake() { printf '%s\n' "$2" > "$RUN_TMP/$1.help"; printf '#!/bin/sh\ncat "%s"\nexit 2\n' "$RUN_TMP/$1.help" > "$RUN_TMP/$1"; chmod +x "$RUN_TMP/$1"; }
V1_HELP="$(cat <<'EOT'
USAGE:
   spoofdpi [global options]

GLOBAL OPTIONS:
   --config string        path to a config file
   --listen-addr string   address to listen on (default: "127.0.0.1:8080")
   --dns-mode string      how names are resolved: udp, https or system
   --dns-addr string      dns server address
   --no-tui               turn the text interface off
   --help, -h             show help
EOT
)"
LEGACY_HELP="$(cat <<'EOT'
Usage of spoofdpi:
  -addr string
    	listen address (default "127.0.0.1")
  -dns-addr string
    	dns address (default "8.8.8.8")
  -enable-doh
    	enable dns-over-https
  -port int
    	port (default 8080)
  -silent
    	do not show the banner
  -system-proxy
    	enable system-wide proxy (default true)
EOT
)"
mkfake fake_v1 "$V1_HELP"; mkfake fake_legacy "$LEGACY_HELP"; mkfake fake_none "Usage: spoofdpi [-h]"

setting_set SPOOF_PATH "$RUN_TMP/fake_v1"
check "v1 build: style is listen" "$(spoofdpi_port_control)" listen
check "v1 build: arguments" "$(build_spoofdpi_args 8081)" "--listen-addr 127.0.0.1:8081 --dns-mode system --no-tui=true"
check "v1 build: no DNS warning" "$(spoof_dns_check 2>&1)" ""
setting_set SPOOF_ARG_STYLE config
build_spoofdpi_args 8081 >/dev/null
check "config style writes listen address" "$(grep -c '^listen-addr = "127.0.0.1:8081"$' "$SPOOF_CONFIG")" 1
check "config style forces system DNS" "$(grep -c '^mode = "system"$' "$SPOOF_CONFIG")" 1
setting_set SPOOF_ARG_STYLE auto

setting_set SPOOF_PATH "$RUN_TMP/fake_legacy"
check "legacy build: style is flags" "$(spoofdpi_port_control)" flags
check "legacy build: arguments" "$(build_spoofdpi_args 8081)" "--addr 127.0.0.1 --port 8081 --enable-doh --dns-addr 1.1.1.1 --silent --system-proxy=false"
setting_set SPOOF_EXTRA_FLAGS "--https-split-mode chunk"
check "extra flags are appended last" "$(build_spoofdpi_args 8081 | awk '{print $(NF-1), $NF}')" "--https-split-mode chunk"
setting_set SPOOF_EXTRA_FLAGS ""

setting_set SPOOF_PATH "$RUN_TMP/fake_none"
check "no-option build: style is none" "$(spoofdpi_port_control)" none
check "no-option build: no arguments" "$(build_spoofdpi_args 8081)" ""
setting_set SPOOF_PORT 9999
check "no-option build: port fixed at 8080" "$(spoof_effective_port)" 8080
spoof_dns_check 2>&1 | grep -q "plaintext DNS" && echo "  DNS leak warning shown: yes" || { fail=$((fail+1)); echo "FAIL: no DNS leak warning"; }
setting_set SPOOF_PATH ""; setting_set SPOOF_PORT 8080

echo "== audit: settings validation and hand-edited file safety"
for v in "SPOOF_PORT 08080:0" "SPOOF_PORT 123456:1" "SPOOF_ARG_STYLE listen:0" "MANAGE_PROXY 1:0" "MANAGE_PROXY yes:1" \
         "SPOOF_EXTRA_FLAGS --a=b --c 5:0" "SPOOF_EXTRA_FLAGS %h:1" "SPOOF_EXTRA_FLAGS \$HOME:1" "SPOOF_EXTRA_FLAGS a\"b:1" "SPOOF_EXTRA_FLAGS a;b:1" \
         "GITHUB_TOKEN ghp_abc123:0" "GITHUB_TOKEN a b:1" "SPOOF_PATH /bin/true:0" "SPOOF_PATH relative/path:1" "SPOOF_PATH /bin/tr ue:1"; do
  exp="${v##*:}"; body="${v%:*}"; key="${body%% *}"; val="${body#* }"
  if setting_valid "$key" "$val"; then got=0; else got=1; fi
  check "valid $key=[$val]" "$got" "$exp"
done
printf 'SPOOF_PORT=abc\nDNS_SERVERS=1.1.1.1;rm -rf /\nSPOOF_ARG_STYLE=bogus\nSPOOF_EXTRA_FLAGS=--x$(touch /tmp/pwned)\nWG_ENDPOINT=a|b:1\nNET_TIMEOUT=9999\n' > "$SETTINGS_FILE"
check "bad port falls back to default" "$(setting_get SPOOF_PORT)" 8080
check "injected DNS value ignored" "$(setting_get DNS_SERVERS)" "1.1.1.1 1.0.0.1"
check "bad style falls back" "$(setting_get SPOOF_ARG_STYLE)" auto
check "injected flags ignored" "$(setting_get SPOOF_EXTRA_FLAGS)" ""
check "bad endpoint ignored" "$(setting_get WG_ENDPOINT)" ""
check "bad timeout ignored" "$(setting_get NET_TIMEOUT)" 30
rm -f "$SETTINGS_FILE"

echo "== audit: GitHub token must not appear in the process list"
curl() { printf 'ARGS:%s\n' "$*"; case "$*" in *"-K -"*) printf 'STDIN:'; cat ;; esac; }
setting_set GITHUB_TOKEN ghp_testtoken123
out="$(http_get "https://api.github.com/repos/x/y/releases/latest")"
echo "$out" | grep -q '^ARGS:.*ghp_testtoken123' && { fail=$((fail+1)); echo "FAIL: token visible in curl arguments"; } || pass=$((pass+1))
echo "$out" | grep -q 'STDIN:header = "Authorization: Bearer ghp_testtoken123"' && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL: token not passed on stdin"; }
out="$(http_get "https://example.com/file" "$RUN_TMP/o")"
echo "$out" | grep -q 'ghp_testtoken123' && { fail=$((fail+1)); echo "FAIL: token sent to a non-GitHub host"; } || pass=$((pass+1))
unset -f curl; rm -f "$SETTINGS_FILE"

echo "== audit: download integrity (GitHub digest)"
printf 'hello' > "$RUN_TMP/payload"
GOOD="$(sha256sum "$RUN_TMP/payload" | awk '{print $1}')"
JSON="{
  \"tag_name\": \"v9\",
  \"assets\": [
    {
      \"name\": \"tool-linux-amd64.tar.gz\",
      \"size\": 10,
      \"digest\": \"sha256:${GOOD}\",
      \"download_count\": 5
    },
    {
      \"name\": \"other.zip\",
      \"digest\": \"sha256:1111111111111111111111111111111111111111111111111111111111111111\",
      \"download_count\": 1
    },
    {
      \"name\": \"nodigest.bin\",
      \"download_count\": 0
    }
  ]
}"
check "digest parsed for first asset" "$(asset_digest "$JSON" tool-linux-amd64.tar.gz)" "$GOOD"
check "digest parsed for second asset" "$(asset_digest "$JSON" other.zip | cut -c1-8)" "11111111"
check "no digest for third asset" "$(asset_digest "$JSON" nodigest.bin)" ""
( verify_download "$RUN_TMP/payload" tool-linux-amd64.tar.gz "$JSON" ) >/dev/null 2>&1; check "matching file accepted" "$?" 0
printf 'tampered' > "$RUN_TMP/bad"
( verify_download "$RUN_TMP/bad" tool-linux-amd64.tar.gz "$JSON" ) >/dev/null 2>&1; check "tampered file rejected" "$?" 1
( verify_download "$RUN_TMP/payload" nodigest.bin "$JSON" ) >/dev/null 2>&1; check "missing digest only warns" "$?" 0

echo "== audit: proxy settings are only undone when this app set them"
set_system_proxy() { echo "set:$1" >> "$RUN_TMP/proxy.log"; }
: > "$RUN_TMP/proxy.log"
clear_managed_proxy
check "user's own proxy left alone" "$(cat "$RUN_TMP/proxy.log")" ""
state_set PROXY_MANAGED 1; clear_managed_proxy
check "app's proxy cleared" "$(cat "$RUN_TMP/proxy.log")" "set:"
check "managed flag reset" "$(state_get PROXY_MANAGED)" 0

echo "== audit: resolvconf fix is safe by default"
install_resolvconf() { echo installed >> "$RUN_TMP/rc.log"; }; configure_dot() { echo dot >> "$RUN_TMP/rc.log"; }
: > "$RUN_TMP/rc.log"; setting_set WG_STRIP_DNS 0
( apply_fix missing_resolvconf 0 "" ) >/dev/null 2>&1
check "primary fix lets the app handle DNS" "$(setting_get WG_STRIP_DNS)" 1
check "primary fix installs no package" "$(cat "$RUN_TMP/rc.log")" ""
( apply_fix missing_resolvconf 1 "" ) >/dev/null 2>&1
check "alternative installs the package" "$(tr '\n' ' ' < "$RUN_TMP/rc.log")" "installed dot "
unset -f install_resolvconf configure_dot
source <(sed -n '/^configure_dot() {/,/^}/p;/^install_resolvconf() {/,/^}/p' "${WORK}/install_t.sh")

echo "== audit: WARP status without a pipeline (SIGPIPE hazard)"
warp_installed() { return 0; }
warp_cli() { echo "Status update: Connected"; }
if warp_running; then got=up; else got=down; fi; check "connected detected" "$got" up
warp_cli() { echo "Status update: Disconnected"; }
if warp_running; then got=up; else got=down; fi; check "disconnected is not connected" "$got" down
warp_cli() { echo "Status update: Connected"; yes "more output" | head -c 300000; }
for _ in 1 2 3 4 5; do if warp_running; then got=up; else got=down; fi; [[ "$got" == up ]] || break; done
check "connected is detected even when the client keeps printing" "$got" up

echo "== audit: encrypted DNS uses a drop-in and never edits resolved.conf"
printf 'stub' > "$WORK/stub-resolv.conf"
printf '[Resolve]\nLLMNR=yes\n' > "$WORK/resolved.conf"
systemctl() { return 0; }; resolvectl() { return 0; }
configure_dot >/dev/null 2>&1
check "drop-in enables DNS-over-TLS" "$(grep -c '^DNSOverTLS=yes$' "$DROPIN_FILE")" 1
check "drop-in blocks fallback servers" "$(grep -c '^FallbackDNS=$' "$DROPIN_FILE")" 1
check "drop-in routes every lookup" "$(grep -c '^Domains=~\.$' "$DROPIN_FILE")" 1
check "drop-in uses your DNS servers" "$(grep -c '^DNS=1.1.1.1 1.0.0.1$' "$DROPIN_FILE")" 1
check "resolv.conf points to the stub" "$(readlink "$RESOLV_CONF")" "$STUB_RESOLV"
check "your resolved.conf is untouched" "$(tr '\n' ' ' < "$WORK/resolved.conf")" "[Resolve] LLMNR=yes "

echo "== audit: unit file hardening and quoting"
printf '#!/bin/sh\nexit 0\n' > "$RUN_TMP/fake_ok"; chmod +x "$RUN_TMP/fake_ok"
setting_set SPOOF_PATH "$RUN_TMP/fake_ok"; setting_set SPOOF_EXTRA_FLAGS "--a=b"
mkdir -p "$(dirname "$SERVICE_FILE")"
write_service 8085 >/dev/null 2>&1
check "unit runs as a dynamic user" "$(grep -c '^DynamicUser=yes$' "$SERVICE_FILE")" 1
check "unit hides home read-only" "$(grep -c '^ProtectHome=read-only$' "$SERVICE_FILE")" 1
check "unit has one ExecStart" "$(grep -c '^ExecStart=' "$SERVICE_FILE")" 1
grep -q '^ExecStart=.*--a=b$' "$SERVICE_FILE" && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL: extra flags missing from ExecStart"; }
setting_set SPOOF_PATH ""; setting_set SPOOF_EXTRA_FLAGS ""

echo "== audit: temporary files are cleaned up after a recovery subshell"
before="$(find "$RUN_TMP" -maxdepth 1 -type d | wc -l)"
( d="$(tmp_dir)"; echo data > "$d/file"; exit 1 ) >/dev/null 2>&1
after="$(find "$RUN_TMP" -maxdepth 1 -type d | wc -l)"
check "subshell temp dir lands under the run folder" "$(( after - before ))" 1
cleanup; [[ -d "$RUN_TMP" ]] && got=left || got=removed; check "cleanup removes the run folder" "$got" removed

echo "== audit: a checksum file must name the asset (no wrong-hash fallback)"
RUN_TMP="$(mktemp -d)"
printf 'hello' > "$RUN_TMP/payload"
GOOD="$(sha256sum "$RUN_TMP/payload" | awk '{print $1}')"
printf '%s  other.tar.gz\n%s  third.tar.gz\n' "$GOOD" "$(printf 'b%.0s' {1..64})" > "$RUN_TMP/sums_many"   # first hash matches the file but belongs to another asset
( verify_checksum "$RUN_TMP/payload" "$RUN_TMP/sums_many" wanted.tar.gz ) >/dev/null 2>&1
check "unlisted asset is not compared with another file's hash" "$?" 1
printf '%s\n' "$GOOD" > "$RUN_TMP/sums_one"
( verify_checksum "$RUN_TMP/payload" "$RUN_TMP/sums_one" anything ) >/dev/null 2>&1
check "a single bare hash is accepted" "$?" 0
printf '%s  wanted.tar.gz\n%s  other\n' "$GOOD" "$(printf 'c%.0s' {1..64})" > "$RUN_TMP/sums_named"
( verify_checksum "$RUN_TMP/payload" "$RUN_TMP/sums_named" wanted.tar.gz ) >/dev/null 2>&1
check "the named asset is accepted" "$?" 0
printf '%s  wanted.tar.gz\n' "$(printf 'd%.0s' {1..64})" > "$RUN_TMP/sums_bad"
( verify_checksum "$RUN_TMP/payload" "$RUN_TMP/sums_bad" wanted.tar.gz ) >/dev/null 2>&1
check "a wrong hash is rejected" "$?" 1
rm -rf "$RUN_TMP"

echo "== audit: WireGuard profile never carries directives that run as root"
RUN_TMP="$(mktemp -d)"
mkdir -p "$WGCF_DIR"
cat > "$WGCF_DIR/wgcf-profile.conf" <<'EOT'
[Interface]
PrivateKey = abc
Address = 172.16.0.2/32
DNS = 1.1.1.1
PostUp = touch /tmp/pwned
preup = echo hi
PreDown=echo bye
  PostDown = echo bye
SaveConfig = true
[Peer]
PublicKey = xyz
Endpoint = engage.cloudflareclient.com:2408
EOT
setting_set WG_STRIP_DNS 1; setting_set WG_ENDPOINT ""
apply_wg_settings >/dev/null 2>&1
check "no root-run directives in the installed profile" "$(grep -ciE '^[[:space:]]*(preup|postup|predown|postdown|saveconfig)' "$WG_CONF")" 0
check "DNS line removed (the app handles DNS)" "$(grep -c '^DNS' "$WG_CONF")" 0
check "keys and addresses preserved" "$(grep -cE '^(PrivateKey = abc|Address = 172.16.0.2/32|PublicKey = xyz)$' "$WG_CONF")" 3
check "profile is readable only by root" "$(stat -c %a "$WG_CONF")" 600
setting_set WG_ENDPOINT "198.51.100.7:2408"; apply_wg_settings >/dev/null 2>&1
check "endpoint override applied" "$(grep -c '^Endpoint = 198.51.100.7:2408$' "$WG_CONF")" 1
setting_set WG_STRIP_DNS 0; setting_set WG_ENDPOINT ""; apply_wg_settings >/dev/null 2>&1
check "DNS kept when the user turns the setting off" "$(grep -c '^DNS = 1.1.1.1$' "$WG_CONF")" 1
rm -f "$SETTINGS_FILE"

echo "== audit: a stale proxy is cleared, your own proxy never is"
set_system_proxy() { echo "set:$1" >> "$RUN_TMP/proxy2.log"; }
spoof_running() { return 1; }
: > "$RUN_TMP/proxy2.log"; state_set PROXY_MANAGED 1; clear_stale_proxy 2>/dev/null
check "stale proxy cleared when SpoofDPI is not running" "$(cat "$RUN_TMP/proxy2.log")" "set:"
check "stale flag reset" "$(state_get PROXY_MANAGED)" 0
spoof_running() { return 0; }
: > "$RUN_TMP/proxy2.log"; state_set PROXY_MANAGED 1; clear_stale_proxy 2>/dev/null
check "proxy kept while SpoofDPI runs" "$(cat "$RUN_TMP/proxy2.log")" ""
spoof_running() { return 1; }
: > "$RUN_TMP/proxy2.log"; state_set PROXY_MANAGED 0; clear_stale_proxy 2>/dev/null
check "your own proxy is never touched" "$(cat "$RUN_TMP/proxy2.log")" ""

echo "== audit: settings are written atomically"
rm -f "$SETTINGS_FILE"; setting_set SPOOF_PORT 8123; setting_set NET_TIMEOUT 45
check "both values stored" "$(setting_get SPOOF_PORT)-$(setting_get NET_TIMEOUT)" "8123-45"
check "no temp files left behind" "$(find "$(dirname "$SETTINGS_FILE")" -maxdepth 1 -name 'tmp.*' | wc -l)" 0
check "settings file is private" "$(stat -c %a "$SETTINGS_FILE")" 600
rm -f "$SETTINGS_FILE"; rm -rf "$RUN_TMP"

echo "== audit: undo restores the exact original state (uninstall.sh)"
cat > "$WORK/restore_test.sh" <<'EOT'
export SECURITY_DNS_SOURCE_ONLY=1
source "$1"
systemctl() { return 0; }; runuser() { return 0; }
mkdir -p "$BACKUP_DIR"
echo "../run/systemd/resolve/stub-resolv.conf" > "$BACKUP_DIR/resolv.conf.link"
: > "$BACKUP_DIR/dropin.absent"
printf 'PATH=/usr/bin\nLANG=en\n' > "$BACKUP_DIR/environment.file"
: > "$USERS_FILE"
mkdir -p "$(dirname "$DROPIN_FILE")"
printf '# Managed by Security DNS\n[Resolve]\n' > "$DROPIN_FILE"
ln -sfn /nonexistent/other "$RESOLV_CONF"
printf 'PATH=/usr/bin\nLANG=en\n# BEGIN security-dns\nhttp_proxy=http://127.0.0.1:8080\n# END security-dns\n' > "$ENV_FILE"
printf '# Managed by Security DNS\n[Resolve]\nDNS=9.9.9.9\n' > "$RESOLVED_CONF"
: > "$BACKUP_DIR/resolved.conf.absent"
PENDING=0
CHOWN_LOG="$2/chown.log"; : > "$CHOWN_LOG"
chown() { echo "$*" >> "$CHOWN_LOG"; }
printf 'kde' > "$BACKUP_DIR/kde-tester.file"
restore_file "$2/kioslaverc" kde-tester "tester:" >/dev/null 2>&1
grep -q -- '-h' "$CHOWN_LOG" && echo chown_nofollow
restore_network_settings >/dev/null 2>&1
[[ ! -e "$DROPIN_FILE" ]] && echo dropin_removed
[[ "$(readlink "$RESOLV_CONF")" == "../run/systemd/resolve/stub-resolv.conf" ]] && echo resolv_restored
[[ "$(cat "$ENV_FILE")" == "$(printf 'PATH=/usr/bin\nLANG=en')" ]] && echo env_restored
[[ ! -e "$RESOLVED_CONF" ]] && echo legacy_resolved_restored
# a program this app did not install must survive a tool removal
mkdir -p "$(dirname "$SPOOF_BIN")"; echo bin > "$SPOOF_BIN"
remove_tool_spoofdpi >/dev/null 2>&1
[[ -e "$SPOOF_BIN" ]] && echo foreign_program_kept
state_set SPOOFDPI_TAG v1
remove_tool_spoofdpi >/dev/null 2>&1
[[ ! -e "$SPOOF_BIN" ]] && echo own_program_removed
EOT
rt="$(bash "$WORK/restore_test.sh" "${WORK}/uninstall_t.sh" "$WORK" 2>&1)"
for token in dropin_removed resolv_restored env_restored legacy_resolved_restored foreign_program_kept own_program_removed chown_nofollow; do
  echo "$rt" | grep -q "^$token$" && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL: undo check '$token' (output: $rt)"; }
done

echo "PASS: $pass  FAIL: $fail"
wait 2>/dev/null
