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
sed "s#/var/lib/security-dns#${WORK}/state#g; s#/usr/local/lib/security-dns#${WORK}/lib#g" "${HERE}/../install.sh" > "${WORK}/install_t.sh"
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
echo "PASS: $pass  FAIL: $fail"
wait 2>/dev/null
