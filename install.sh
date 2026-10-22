#!/usr/bin/env bash
# =============================================================================
# Security DNS - Linux CLI (installer + control menu)
# Repository : https://github.com/arcalc/setup_privacy
# License    : MIT
# Portfolio  : https://arcalc.github.io/arcalc/
# Security   : thearcalc@protonmail.com  (never report vulnerabilities publicly)
#
# Tools (each one can be controlled independently):
#   spoofdpi   local proxy that splits the TLS handshake to bypass DPI
#   warp       Cloudflare WARP client (encrypted tunnel to Cloudflare)
#   wireguard  the same WARP tunnel through WireGuard, profile made by wgcf
#
# Actions per tool: install, start, stop, enable (autostart), disable, uninstall.
# Kill switch: stops every tool at once and keeps encrypted DNS (DoT) on.
#
# Smart recovery: when a step fails, the script classifies the error, explains
# it, proposes an automatic fix, and retries after you approve.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/arcalc/setup_privacy/main/cli/install.sh | sudo bash
#   sudo security-dns [--menu | --kill | --restore | --update | --uninstall | --version]
# =============================================================================

set -uo pipefail

readonly SCRIPT_VERSION="3.0.0"
readonly REPO_RAW="https://raw.githubusercontent.com/arcalc/setup_privacy/main/cli"
readonly PORTFOLIO_URL="https://arcalc.github.io/arcalc/"
readonly CONTACT_EMAIL="thearcalc@protonmail.com"
readonly SPOOFDPI_REPO="xvzc/SpoofDPI"
readonly WGCF_REPO="ViRb3/wgcf"

readonly APP_BIN="/usr/local/bin/security-dns"
readonly LIB_DIR="/usr/local/lib/security-dns"
readonly UNINSTALL_PATH="${LIB_DIR}/uninstall.sh"
readonly SPOOF_CONFIG="${LIB_DIR}/spoofdpi.toml"
readonly DESKTOP_FILE="/usr/share/applications/security-dns.desktop"
readonly STATE_DIR="/var/lib/security-dns"
readonly STATE_FILE="${STATE_DIR}/state.env"
readonly SETTINGS_FILE="${STATE_DIR}/settings.env"
readonly BACKUP_DIR="${STATE_DIR}/backup"
readonly USERS_FILE="${BACKUP_DIR}/users.tsv"
readonly SPOOF_BIN_DEFAULT="/usr/local/bin/spoofdpi"
readonly SERVICE_NAME="security-dns"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly WG_IFACE="security-dns"
readonly WG_SERVICE="wg-quick@${WG_IFACE}"
readonly WG_CONF="/etc/wireguard/${WG_IFACE}.conf"
readonly WGCF_BIN_DEFAULT="/usr/local/bin/wgcf"
readonly WGCF_DIR="${STATE_DIR}/wgcf"
readonly RESOLVED_CONF="/etc/systemd/resolved.conf"
readonly RESOLV_CONF="/etc/resolv.conf"
readonly STUB_RESOLV="/run/systemd/resolve/stub-resolv.conf"
readonly ENV_FILE="/etc/environment"

readonly WARP_APT_LIST="/etc/apt/sources.list.d/cloudflare-client.list"
readonly WARP_APT_KEY="/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
readonly WARP_APT_KEY_URL="https://pkg.cloudflareclient.com/pubkey.gpg"
readonly WARP_DNF_REPO="/etc/yum.repos.d/cloudflare-warp.repo"
readonly WARP_DNF_URL="https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo"

PM=""
UI_LANG="en"
TMP_DIR=""
ERR_LOG=""
RELEASE_TAG=""
ASSET_URL=""
SUMS_URL=""

# -----------------------------------------------------------------------------
# Customizable settings (stored in settings.env, edited from the Settings menu)
# -----------------------------------------------------------------------------
readonly SETTING_KEYS=(SPOOF_PORT DNS_SERVERS WG_ENDPOINT WG_STRIP_DNS SPOOF_ARG_STYLE
  SPOOF_EXTRA_FLAGS SPOOF_PATH WGCF_PATH NET_TIMEOUT GITHUB_TOKEN)

declare -A SETTING_DEFAULT=(
  [SPOOF_PORT]="8080"
  [DNS_SERVERS]="1.1.1.1 1.0.0.1"
  [WG_ENDPOINT]=""
  [WG_STRIP_DNS]="1"
  [SPOOF_ARG_STYLE]="auto"
  [SPOOF_EXTRA_FLAGS]=""
  [SPOOF_PATH]=""
  [WGCF_PATH]=""
  [NET_TIMEOUT]="30"
  [GITHUB_TOKEN]=""
)

# -----------------------------------------------------------------------------
# User-facing text. Only strings are translated; code stays in English.
# -----------------------------------------------------------------------------
declare -A MSG_EN=(
  [lang_title]="Select your language:"
  [lang_prompt]="Enter 1 or 2: "
  [lang_bad]="Please enter 1 or 2."
  [need_root]="Run this as root: sudo security-dns"
  [press_enter]="Press Enter to continue."
  [choose]="Choose: "
  [bad_choice]="Unknown option. Choose from the list."
  [menu_head]="Security DNS v%s"
  [menu_quick]="Quick modes (start one tool and stop the others):"
  [menu_1]="1) SpoofDPI          keeps your public IP; bypasses DPI on this computer"
  [menu_2]="2) Cloudflare WARP   hides destination IPs from your ISP; changes your public IP"
  [menu_3]="3) WireGuard (wgcf)  the same WARP tunnel through WireGuard; changes your public IP"
  [menu_manage]="Manage:"
  [menu_4]="4) Advanced Tool Manager  install, start, stop, enable, disable or remove each tool"
  [menu_5]="5) Settings               ports, DNS servers, WireGuard endpoint, tool paths"
  [menu_6]="6) Status"
  [menu_7]="7) Check for updates"
  [menu_8]="8) Restore original settings  undo DNS and proxy changes; keeps the app and tools"
  [menu_9]="9) KILL SWITCH  turn off every tool now; encrypted DNS stays on"
  [menu_a]="a) About, contact and security policy"
  [menu_u]="u) Uninstall everything"
  [menu_q]="q) Quit"
  [tunnel_warn]="WARNING: this tool hides destination IPs from your ISP, but your public IP changes, your apparent country may change (traffic exits at the nearest Cloudflare data center), and traffic volume stays visible to your ISP."
  [continue_q]="Continue?"
  [unchanged]="Nothing was changed."
  [done_ok]="Done."
  [op_failed]="The operation did not complete. See the messages above."
  [tm_head]="Advanced Tool Manager"
  [tm_hint]="Pick a tool to control it on its own. Tools do not depend on each other."
  [tm_all]="i) Install all missing tools"
  [tm_kill]="k) KILL SWITCH: turn off every tool now"
  [tm_back]="b) Back"
  [tool_spoofdpi]="SpoofDPI - a local proxy that splits your TLS handshake so DPI equipment cannot read website names. Keeps your public IP."
  [tool_warp]="Cloudflare WARP - an encrypted tunnel to Cloudflare that hides destination IPs from your ISP. Changes your public IP and may change your apparent country."
  [tool_wireguard]="WireGuard (wgcf) - the same Cloudflare WARP tunnel run by the standard WireGuard client with a profile made by wgcf. Same trade-offs as WARP."
  [act_install]="1) Install    - download and install the tool; nothing starts yet"
  [act_start]="2) Start      - run it now (stops again on Stop or reboot unless enabled)"
  [act_stop]="3) Stop       - stop it now; nothing is deleted"
  [act_enable]="4) Enable     - start it automatically at boot"
  [act_disable]="5) Disable    - do not start it automatically"
  [act_uninstall]="6) Uninstall  - stop it and delete what this app installed for it"
  [st_installed]="installed"
  [st_missing]="not installed"
  [st_running]="running"
  [st_stopped]="stopped"
  [st_enabled]="autostart on"
  [st_disabled]="autostart off"
  [stat_dns]="Encrypted DNS"
  [kill_start]="Turning off all tools..."
  [kill_done]="All tools are off. Encrypted DNS is on."
  [kill_partial]="Some tools could not be stopped. Check the messages above."
  [restore_q]="Restore your original network, DNS and proxy settings and stop all tools? The app and tools stay installed."
  [restore_done]="Original settings restored. The app and tools are still installed."
  [restore_fail]="Restore did not complete. Check the messages above."
  [uninst_q]="Uninstall Security DNS completely and restore your original settings?"
  [set_head]="Settings"
  [set_hint]="Type a number to change a setting. r = reset all to defaults, b = back."
  [set_SPOOF_PORT]="SpoofDPI port - where SpoofDPI listens on this computer (default 8080). If busy, a free port is chosen for you."
  [set_DNS_SERVERS]="DNS servers - encrypted DNS servers used for every lookup, space separated (default 1.1.1.1 1.0.0.1). Use ip#hostname to pin a TLS name."
  [set_WG_ENDPOINT]="WireGuard endpoint - replaces the server address (host:port) in the WireGuard profile. Empty keeps Cloudflare's default."
  [set_WG_STRIP_DNS]="WireGuard DNS handling - 1 = this app handles DNS (no resolvconf needed), 0 = the profile sets DNS itself."
  [set_SPOOF_ARG_STYLE]="SpoofDPI argument style - auto, config, flags, port or none. Auto reads the installed build's --help."
  [set_SPOOF_EXTRA_FLAGS]="SpoofDPI extra flags - added to the SpoofDPI command line. Advanced."
  [set_SPOOF_PATH]="SpoofDPI program path - use your own binary instead of the downloaded one. Empty = managed copy."
  [set_WGCF_PATH]="wgcf program path - use your own wgcf binary. Empty = managed copy."
  [set_NET_TIMEOUT]="Network timeout - seconds to wait for connections (5-300, default 30)."
  [set_GITHUB_TOKEN]="GitHub token - optional, avoids GitHub download rate limits. Stored only on this computer."
  [set_current]="current"
  [set_prompt]="New value (empty keeps it, '-' clears it): "
  [set_saved]="Saved."
  [set_invalid]="That value is not valid for this setting."
  [set_reset_q]="Reset all settings to their defaults?"
  [pd_what]="What went wrong:"
  [pd_prop]="Proposed solution:"
  [pd_details]="Technical details:"
  [pd_choose]="[a] Apply fix   [x] Cancel : "
  [pd_choose_alt]="[a] Apply fix   [s] %s   [x] Cancel : "
  [fix_applied]="Fix applied. Resuming the operation..."
  [fix_failed]="The fix could not be applied."
  [giving_up]="The same problem keeps happening, so the operation was stopped."
  [cancelled]="Cancelled."
  [p_port_in_use_t]="Port is already taken"
  [p_port_in_use_e]="Another application is using the port SpoofDPI needs."
  [p_port_in_use_f]="I will choose a free port automatically and save it in Settings."
  [p_unsupported_flag_t]="SpoofDPI does not accept these options"
  [p_unsupported_flag_e]="The installed SpoofDPI version rejected the startup options."
  [p_unsupported_flag_f]="I will switch to a different option style (config file, flags, port only, or none) and retry."
  [p_missing_resolvconf_t]="resolvconf is missing"
  [p_missing_resolvconf_e]="WireGuard needs the resolvconf tool to set DNS, and it is not installed."
  [p_missing_resolvconf_f]="I will install resolvconf (openresolv on Arch, Fedora and openSUSE) with your package manager."
  [p_missing_resolvconf_a]="Let this app handle DNS instead (recommended)"
  [p_missing_tool_t]="A required program is missing"
  [p_missing_tool_e]="A program this operation needs is not installed."
  [p_missing_tool_f]="I will install it with your package manager and retry."
  [p_permission_t]="Permission denied"
  [p_permission_e]="The system refused the operation because of missing permissions."
  [p_permission_f]="I will retry once. If it fails again, run the program with sudo."
  [p_network_t]="Network problem"
  [p_network_e]="A connection timed out or the server could not be reached."
  [p_network_f]="I will wait a moment, raise the network timeout, and retry."
  [p_ratelimit_t]="Download limit reached"
  [p_ratelimit_e]="GitHub is limiting requests from your network."
  [p_ratelimit_f]="I will wait 30 seconds and retry. A GitHub token in Settings avoids this."
  [p_resolved_missing_t]="systemd-resolved is missing"
  [p_resolved_missing_e]="Encrypted DNS needs systemd-resolved, which is not available."
  [p_resolved_missing_f]="I will install and enable systemd-resolved, then retry."
  [p_conflict_t]="Two tunnels cannot run together"
  [p_conflict_e]="Cloudflare WARP and WireGuard both route all traffic, so they conflict."
  [p_conflict_f]="I will stop the other tunnel and then start this one."
  [p_no_asset_t]="No download found for this system"
  [p_no_asset_e]="The project does not publish a build for this operating system or CPU."
  [p_no_asset_f]="I will open Settings so you can point to a program you built yourself."
  [p_unknown_t]="Unexpected error"
  [p_unknown_e]="The operation failed for a reason I do not recognize."
  [p_unknown_f]="I will retry the operation. The technical details below show the cause."
  [port_busy]="Port %s is taken by another application. Choosing another port."
  [port_switched]="SpoofDPI will use port %s."
  [preflight_ok]="SpoofDPI started correctly in a test run."
  [preflight_fail]="SpoofDPI exited during the test run (exit code %s). Its output follows."
  [start_fail]="SpoofDPI did not start and listen on its port. The service log follows."
  [start_ok]="SpoofDPI is listening on 127.0.0.1:%s."
  [first_run]="Installing Security DNS for the first time."
  [first_start_q]="Download and start SpoofDPI now?"
  [done_title]="Security DNS is installed."
  [done_menu]="Open the menu any time with: sudo security-dns"
  [done_next]="Log out and back in, restart your browsers, then enable ECH and disable QUIC (see README.md)."
  [about_head]="About Security DNS"
  [about_dev]="Developer portfolio : %s"
  [about_mail]="Support and security email : %s"
  [about_sec_title]="Security policy"
  [about_sec_text]="Do NOT open public issues for security vulnerabilities. Report them privately by email to %s, or through GitHub's Private Vulnerability Reporting (repository Security tab, Report a vulnerability). This protects the community until a fix is released."
  [about_license]="License: MIT"
)

declare -A MSG_AR=(
  [lang_title]="اختر لغتك:"
  [lang_prompt]="أدخل 1 أو 2: "
  [lang_bad]="يرجى إدخال 1 أو 2."
  [need_root]="شغّل هذا الأمر بصلاحيات المسؤول: sudo security-dns"
  [press_enter]="اضغط Enter للمتابعة."
  [choose]="اختر: "
  [bad_choice]="خيار غير معروف. اختر من القائمة."
  [menu_head]="Security DNS الإصدار %s"
  [menu_quick]="أوضاع سريعة (تشغّل أداة واحدة وتوقف البقية):"
  [menu_1]="1) SpoofDPI          يحافظ على عنوان IP العام؛ يتجاوز فحص الحزم على هذا الجهاز"
  [menu_2]="2) Cloudflare WARP   يخفي عناوين الوجهات عن مزود الإنترنت؛ يغيّر عنوان IP العام"
  [menu_3]="3) WireGuard (wgcf)  نفس نفق WARP عبر WireGuard؛ يغيّر عنوان IP العام"
  [menu_manage]="الإدارة:"
  [menu_4]="4) مدير الأدوات المتقدم  تثبيت، تشغيل، إيقاف، تفعيل، تعطيل أو حذف كل أداة"
  [menu_5]="5) الإعدادات             المنافذ، خوادم DNS، نقطة اتصال WireGuard، مسارات الأدوات"
  [menu_6]="6) الحالة"
  [menu_7]="7) التحقق من التحديثات"
  [menu_8]="8) استعادة الإعدادات الأصلية  تراجع عن تغييرات DNS والوكيل؛ يبقي التطبيق والأدوات"
  [menu_9]="9) مفتاح الإيقاف الطارئ  أوقف كل الأدوات الآن؛ يبقى DNS المشفّر مفعّلاً"
  [menu_a]="a) حول التطبيق والتواصل وسياسة الأمان"
  [menu_u]="u) إلغاء التثبيت بالكامل"
  [menu_q]="q) خروج"
  [tunnel_warn]="تحذير: تخفي هذه الأداة عناوين الوجهات عن مزود الإنترنت، لكن عنوان IP العام سيتغير، وقد يتغير البلد الظاهر لك (يخرج الاتصال من أقرب مركز بيانات لـ Cloudflare)، ويبقى حجم الحركة مرئياً لمزود الإنترنت."
  [continue_q]="هل تريد المتابعة؟"
  [unchanged]="لم يتم تغيير أي شيء."
  [done_ok]="تم."
  [op_failed]="لم تكتمل العملية. راجع الرسائل أعلاه."
  [tm_head]="مدير الأدوات المتقدم"
  [tm_hint]="اختر أداة للتحكم بها بشكل مستقل. الأدوات لا تعتمد على بعضها."
  [tm_all]="i) تثبيت كل الأدوات الناقصة"
  [tm_kill]="k) مفتاح الإيقاف الطارئ: أوقف كل الأدوات الآن"
  [tm_back]="b) رجوع"
  [tool_spoofdpi]="SpoofDPI - وكيل محلي يقسّم مصافحة TLS حتى لا تتمكن أجهزة الفحص من قراءة أسماء المواقع. يحافظ على عنوان IP العام."
  [tool_warp]="Cloudflare WARP - نفق مشفّر إلى Cloudflare يخفي عناوين الوجهات عن مزود الإنترنت. يغيّر عنوان IP العام وقد يغيّر البلد الظاهر لك."
  [tool_wireguard]="WireGuard (wgcf) - نفس نفق Cloudflare WARP لكن عبر عميل WireGuard القياسي بملف أنشأه wgcf. نفس سلبيات WARP."
  [act_install]="1) تثبيت   - تنزيل الأداة وتثبيتها؛ لا يبدأ شيء بعد"
  [act_start]="2) تشغيل   - شغّلها الآن (تتوقف عند الإيقاف أو إعادة التشغيل ما لم تُفعَّل)"
  [act_stop]="3) إيقاف   - أوقفها الآن؛ لا يُحذف شيء"
  [act_enable]="4) تفعيل   - تبدأ تلقائياً عند الإقلاع"
  [act_disable]="5) تعطيل   - لا تبدأ تلقائياً"
  [act_uninstall]="6) حذف     - أوقفها واحذف ما ثبّته التطبيق لها"
  [st_installed]="مثبّتة"
  [st_missing]="غير مثبّتة"
  [st_running]="تعمل"
  [st_stopped]="متوقفة"
  [st_enabled]="البدء التلقائي مفعّل"
  [st_disabled]="البدء التلقائي معطّل"
  [stat_dns]="DNS المشفّر"
  [kill_start]="جارٍ إيقاف كل الأدوات..."
  [kill_done]="كل الأدوات متوقفة. DNS المشفّر مفعّل."
  [kill_partial]="تعذّر إيقاف بعض الأدوات. راجع الرسائل أعلاه."
  [restore_q]="هل تريد استعادة إعدادات الشبكة والـDNS والوكيل الأصلية وإيقاف كل الأدوات؟ يبقى التطبيق والأدوات مثبّتة."
  [restore_done]="تمت استعادة الإعدادات الأصلية. ما زال التطبيق والأدوات مثبّتة."
  [restore_fail]="لم تكتمل عملية الاستعادة. راجع الرسائل أعلاه."
  [uninst_q]="هل تريد إلغاء تثبيت Security DNS بالكامل واستعادة إعداداتك الأصلية؟"
  [set_head]="الإعدادات"
  [set_hint]="اكتب رقماً لتغيير إعداد. r = إعادة كل الإعدادات للافتراضي، b = رجوع."
  [set_SPOOF_PORT]="منفذ SpoofDPI - المنفذ الذي يستمع عليه SpoofDPI على هذا الجهاز (الافتراضي 8080). إن كان مشغولاً يُختار منفذ حر تلقائياً."
  [set_DNS_SERVERS]="خوادم DNS - خوادم DNS المشفّرة لكل الاستعلامات، مفصولة بمسافة (الافتراضي 1.1.1.1 1.0.0.1). استخدم ip#hostname لتحديد اسم TLS."
  [set_WG_ENDPOINT]="نقطة اتصال WireGuard - تستبدل عنوان الخادم (host:port) في ملف WireGuard. الفارغ يبقي افتراضي Cloudflare."
  [set_WG_STRIP_DNS]="التعامل مع DNS في WireGuard - 1 = يتولى التطبيق DNS (دون حاجة لـ resolvconf)، 0 = الملف يضبط DNS بنفسه."
  [set_SPOOF_ARG_STYLE]="نمط خيارات SpoofDPI - auto أو config أو flags أو port أو none. وضع auto يقرأ --help للإصدار المثبّت."
  [set_SPOOF_EXTRA_FLAGS]="خيارات إضافية لـ SpoofDPI - تُضاف إلى سطر أوامر SpoofDPI. للمتقدمين."
  [set_SPOOF_PATH]="مسار برنامج SpoofDPI - استخدم ملفك التنفيذي بدل المنزّل. الفارغ = النسخة المُدارة."
  [set_WGCF_PATH]="مسار برنامج wgcf - استخدم ملف wgcf الخاص بك. الفارغ = النسخة المُدارة."
  [set_NET_TIMEOUT]="مهلة الشبكة - ثوانٍ لانتظار الاتصالات (5-300، الافتراضي 30)."
  [set_GITHUB_TOKEN]="رمز GitHub - اختياري، يتجنب حدود التنزيل من GitHub. يُحفظ على هذا الجهاز فقط."
  [set_current]="الحالي"
  [set_prompt]="القيمة الجديدة (الفارغ يبقيها، و'-' يمسحها): "
  [set_saved]="تم الحفظ."
  [set_invalid]="هذه القيمة غير صالحة لهذا الإعداد."
  [set_reset_q]="هل تريد إعادة كل الإعدادات إلى قيمها الافتراضية؟"
  [pd_what]="ما الذي حدث:"
  [pd_prop]="الحل المقترح:"
  [pd_details]="التفاصيل التقنية:"
  [pd_choose]="[a] تطبيق الحل   [x] إلغاء : "
  [pd_choose_alt]="[a] تطبيق الحل   [s] %s   [x] إلغاء : "
  [fix_applied]="تم تطبيق الحل. جارٍ استئناف العملية..."
  [fix_failed]="تعذّر تطبيق الحل."
  [giving_up]="تتكرر المشكلة نفسها، لذلك أُوقفت العملية."
  [cancelled]="تم الإلغاء."
  [p_port_in_use_t]="المنفذ مشغول"
  [p_port_in_use_e]="تطبيق آخر يستخدم المنفذ الذي يحتاجه SpoofDPI."
  [p_port_in_use_f]="سأختار منفذاً حراً تلقائياً وأحفظه في الإعدادات."
  [p_unsupported_flag_t]="SpoofDPI لا يقبل هذه الخيارات"
  [p_unsupported_flag_e]="رفض إصدار SpoofDPI المثبّت خيارات التشغيل."
  [p_unsupported_flag_f]="سأنتقل إلى نمط خيارات مختلف (ملف إعداد أو خيارات أو منفذ فقط أو بدون) وأعيد المحاولة."
  [p_missing_resolvconf_t]="أداة resolvconf غير موجودة"
  [p_missing_resolvconf_e]="يحتاج WireGuard إلى أداة resolvconf لضبط DNS وهي غير مثبّتة."
  [p_missing_resolvconf_f]="سأثبّت resolvconf (أو openresolv على Arch وFedora وopenSUSE) عبر مدير الحزم."
  [p_missing_resolvconf_a]="دع التطبيق يتولى DNS بدلاً من ذلك (موصى به)"
  [p_missing_tool_t]="برنامج مطلوب غير موجود"
  [p_missing_tool_e]="برنامج تحتاجه هذه العملية غير مثبّت."
  [p_missing_tool_f]="سأثبّته عبر مدير الحزم وأعيد المحاولة."
  [p_permission_t]="تم رفض الإذن"
  [p_permission_e]="رفض النظام العملية بسبب نقص الصلاحيات."
  [p_permission_f]="سأعيد المحاولة مرة واحدة. إن فشلت فشغّل البرنامج بـ sudo."
  [p_network_t]="مشكلة في الشبكة"
  [p_network_e]="انتهت مهلة اتصال أو تعذّر الوصول إلى الخادم."
  [p_network_f]="سأنتظر قليلاً وأرفع مهلة الشبكة وأعيد المحاولة."
  [p_ratelimit_t]="تم بلوغ حد التنزيل"
  [p_ratelimit_e]="تقيّد GitHub الطلبات القادمة من شبكتك."
  [p_ratelimit_f]="سأنتظر 30 ثانية وأعيد المحاولة. رمز GitHub في الإعدادات يتجنب هذا."
  [p_resolved_missing_t]="systemd-resolved غير موجود"
  [p_resolved_missing_e]="يحتاج DNS المشفّر إلى systemd-resolved وهو غير متاح."
  [p_resolved_missing_f]="سأثبّت systemd-resolved وأفعّله ثم أعيد المحاولة."
  [p_conflict_t]="لا يمكن تشغيل نفقين معاً"
  [p_conflict_e]="يوجّه Cloudflare WARP وWireGuard كل الحركة، لذلك يتعارضان."
  [p_conflict_f]="سأوقف النفق الآخر ثم أشغّل هذا."
  [p_no_asset_t]="لا يوجد ملف تنزيل لهذا النظام"
  [p_no_asset_e]="لا ينشر المشروع إصداراً لهذا النظام أو هذا المعالج."
  [p_no_asset_f]="سأفتح الإعدادات لتحدد برنامجاً بنيته بنفسك."
  [p_unknown_t]="خطأ غير متوقع"
  [p_unknown_e]="فشلت العملية لسبب لا أتعرف عليه."
  [p_unknown_f]="سأعيد المحاولة. توضح التفاصيل التقنية أدناه السبب."
  [port_busy]="المنفذ %s مشغول بتطبيق آخر. سيتم اختيار منفذ آخر."
  [port_switched]="سيستخدم SpoofDPI المنفذ %s."
  [preflight_ok]="بدأ SpoofDPI بنجاح في الاختبار الأولي."
  [preflight_fail]="أُغلق SpoofDPI أثناء الاختبار الأولي (رمز الخروج %s). المخرجات التالية."
  [start_fail]="لم يبدأ SpoofDPI ولم يستمع على منفذه. سجل الخدمة التالي."
  [start_ok]="SpoofDPI يستمع الآن على 127.0.0.1:%s."
  [first_run]="جارٍ تثبيت Security DNS لأول مرة."
  [first_start_q]="هل تريد تنزيل SpoofDPI وتشغيله الآن؟"
  [done_title]="تم تثبيت Security DNS."
  [done_menu]="افتح القائمة في أي وقت بالأمر: sudo security-dns"
  [done_next]="سجّل الخروج ثم الدخول مجدداً، وأعد تشغيل المتصفح، ثم فعّل ECH وعطّل QUIC (راجع README.md)."
  [about_head]="حول Security DNS"
  [about_dev]="موقع المطوّر : %s"
  [about_mail]="البريد للدعم والأمان : %s"
  [about_sec_title]="سياسة الأمان"
  [about_sec_text]="لا تفتح مشكلات عامة (public issues) للثغرات الأمنية. أبلغ عنها بشكل خاص عبر البريد %s أو عبر ميزة الإبلاغ الخاص عن الثغرات في GitHub (تبويب Security في المستودع ثم Report a vulnerability). هذا يحمي المجتمع حتى يصدر الإصلاح."
  [about_license]="الرخصة: MIT"
)

# msg <key> [printf args...]: prints the text in the selected language.
msg() {
  local key="$1"; shift
  local text
  if [[ "$UI_LANG" == "ar" ]]; then
    text="${MSG_AR[$key]:-${MSG_EN[$key]:-$key}}"
  else
    text="${MSG_EN[$key]:-$key}"
  fi
  # shellcheck disable=SC2059
  printf -- "$text" "$@"
}

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }

cleanup() {
  [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
  [[ -n "$ERR_LOG" && -f "$ERR_LOG" ]] && rm -f "$ERR_LOG"
  return 0
}
trap cleanup EXIT

confirm() {  # <question>; returns 0 for yes
  local reply=""
  read -r -p "$1 [y/N] " reply || true
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

pause() { local _=""; read -r -p "$(msg press_enter)" _ || true; }

reconnect_terminal() {
  if [[ ! -t 0 && -r /dev/tty ]]; then
    exec </dev/tty
  fi
}

choose_language() {
  reconnect_terminal
  local answer=""
  while true; do
    printf '\n  %s  /  %s\n\n  1) English\n  2) العربية\n\n' "${MSG_EN[lang_title]}" "${MSG_AR[lang_title]}"
    read -r -p "${MSG_EN[lang_prompt]}" answer || answer="1"
    case "$answer" in
      1) UI_LANG="en"; return 0 ;;
      2) UI_LANG="ar"; return 0 ;;
      *) printf '%s / %s\n' "${MSG_EN[lang_bad]}" "${MSG_AR[lang_bad]}" ;;
    esac
  done
}

# -----------------------------------------------------------------------------
# State (internal bookkeeping) and settings (user customizable)
# -----------------------------------------------------------------------------
state_get() {  # <key>
  [[ -f "$STATE_FILE" ]] || return 0
  sed -n "s/^${1}=//p" "$STATE_FILE" | tail -n1
  return 0
}

state_set() {  # <key> <value>
  mkdir -p "$STATE_DIR"
  touch "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
  sed -i "/^${1}=/d" "$STATE_FILE"
  printf '%s=%s\n' "$1" "$2" >> "$STATE_FILE"
}

setting_get() {  # <key>
  local line=""
  if [[ -f "$SETTINGS_FILE" ]]; then
    line="$(grep -m1 "^${1}=" "$SETTINGS_FILE" || true)"
  fi
  if [[ -n "$line" ]]; then
    printf '%s' "${line#*=}"
  else
    printf '%s' "${SETTING_DEFAULT[$1]:-}"
  fi
}

setting_set() {  # <key> <value>
  mkdir -p "$STATE_DIR"
  touch "$SETTINGS_FILE"
  chmod 0600 "$SETTINGS_FILE"
  local tmp
  tmp="$(mktemp)"
  grep -v "^${1}=" "$SETTINGS_FILE" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  cat "$tmp" > "$SETTINGS_FILE"
  rm -f "$tmp"
}

# setting_valid <key> <value>: returns 0 when the value is acceptable.
setting_valid() {
  local key="$1" value="$2" item re
  case "$key" in
    SPOOF_PORT)  [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 )) ;;
    DNS_SERVERS)
      [[ -n "$value" ]] || return 1
      for item in $value; do
        [[ "$item" =~ ^[0-9A-Fa-f:.]+(#[A-Za-z0-9.-]+)?$ ]] || return 1
      done ;;
    WG_ENDPOINT)
      re='^[][A-Za-z0-9._:-]+:[0-9]{1,5}$'
      [[ -z "$value" || "$value" =~ $re ]] ;;
    WG_STRIP_DNS) [[ "$value" == "0" || "$value" == "1" ]] ;;
    SPOOF_ARG_STYLE) [[ "$value" =~ ^(auto|config|flags|port|none)$ ]] ;;
    SPOOF_EXTRA_FLAGS) [[ ! "$value" =~ [\;\&\|\$\`\<\>] ]] ;;
    SPOOF_PATH|WGCF_PATH) [[ -z "$value" || ( "$value" == /* && -x "$value" ) ]] ;;
    NET_TIMEOUT) [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 5 && value <= 300 )) ;;
    GITHUB_TOKEN) [[ ! "$value" =~ [[:space:]] ]] ;;
    *) return 1 ;;
  esac
}

spoof_bin() { local p; p="$(setting_get SPOOF_PATH)"; printf '%s' "${p:-$SPOOF_BIN_DEFAULT}"; }
wgcf_bin()  { local p; p="$(setting_get WGCF_PATH)";  printf '%s' "${p:-$WGCF_BIN_DEFAULT}"; }

# -----------------------------------------------------------------------------
# Preflight and package manager
# -----------------------------------------------------------------------------
require_root() {
  [[ "${EUID}" -eq 0 ]] || { printf '%s\n' "$(msg need_root)" >&2; exit 1; }
}

check_platform() {
  [[ "$(uname -s)" == "Linux" ]] || die "This installer supports Linux only."
  [[ "$(uname -m)" == "x86_64" ]] || die "Only x86_64 (amd64) is supported. Detected: $(uname -m)."
  [[ -d /run/systemd/system ]] || die "systemd is required but was not detected."
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then PM="apt"
  elif command -v dnf >/dev/null 2>&1; then PM="dnf"
  elif command -v pacman >/dev/null 2>&1; then PM="pacman"
  elif command -v zypper >/dev/null 2>&1; then PM="zypper"
  else PM=""
  fi
}

pm_install() {  # <packages...>
  case "$PM" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf)    dnf install -y -q "$@" ;;
    pacman) pacman -S --needed --noconfirm "$@" ;;
    zypper) zypper --non-interactive install "$@" ;;
    *)      die "No supported package manager found. Install these packages manually: $*" ;;
  esac
}

# package_for_tool <command>: prints the package that provides the command.
package_for_tool() {
  case "$1" in
    curl|wget|tar|gawk|sed) printf '%s' "$1" ;;
    gpg|gpg2) case "$PM" in dnf) printf 'gnupg2' ;; zypper) printf 'gpg2' ;; *) printf 'gnupg' ;; esac ;;
    wg|wg-quick) printf 'wireguard-tools' ;;
    runuser|nsenter) printf 'util-linux' ;;
    timeout) printf 'coreutils' ;;
    journalctl|systemctl) printf 'systemd' ;;
    resolvectl) case "$PM" in apt) printf 'systemd-resolved' ;; *) printf 'systemd' ;; esac ;;
    ss|ip) case "$PM" in dnf) printf 'iproute' ;; *) printf 'iproute2' ;; esac ;;
    *) printf '' ;;
  esac
}

install_base_packages() {
  local cmd
  for cmd in curl tar; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      warn "Missing tool: ${cmd}"
      pm_install ca-certificates "$cmd"
    fi
  done
  command -v resolvectl >/dev/null 2>&1 || warn "resolvectl not found; systemd-resolved may be missing."
}

# -----------------------------------------------------------------------------
# Network helpers (timeouts and optional GitHub token come from Settings)
# -----------------------------------------------------------------------------
http_get() {  # <url> [output file]
  local url="$1" out="${2:-}" token
  local -a args=(-fsSL --retry 2 --connect-timeout "$(setting_get NET_TIMEOUT)" --max-time 900)
  token="$(setting_get GITHUB_TOKEN)"
  if [[ -n "$token" && "$url" == https://api.github.com/* ]]; then
    args+=(-H "Authorization: Bearer ${token}")
  fi
  if [[ -n "$out" ]]; then
    curl "${args[@]}" -o "$out" "$url"
  else
    curl "${args[@]}" -H 'Accept: application/vnd.github+json' "$url"
  fi
}

# Local port checks use bash's /dev/tcp, so no external tool is needed.
port_in_use() {  # <port>
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

find_free_port() {  # <start>
  local p="$1" last=$(( $1 + 200 ))
  while (( p <= last && p <= 65535 )); do
    if ! port_in_use "$p"; then printf '%s' "$p"; return 0; fi
    p=$(( p + 1 ))
  done
  return 1
}

# -----------------------------------------------------------------------------
# Smart recovery: classify an error, explain it, offer a fix, then retry.
# Operations run in a subshell with 'set -e'. Their output is shown and kept in
# ERR_LOG so the failure can be analyzed.
# -----------------------------------------------------------------------------
classify_problem() {  # <text>; prints a problem kind
  local t="${1,,}" re
  re='conflict:(warp|wireguard)'
  [[ "$t" =~ $re ]] && { echo conflict; return; }
  re='address already in use|already in use|only one usage of each socket'
  [[ "$t" =~ $re ]] && { echo port_in_use; return; }
  re='flag provided but not defined|unknown flag|unknown option|unrecognized option|unknown shorthand'
  [[ "$t" =~ $re ]] && { echo unsupported_flag; return; }
  re='resolvconf: (command )?not found|resolvconf.*not found|openresolv'
  [[ "$t" =~ $re ]] && { echo missing_resolvconf; return; }
  re='systemd-resolved.*(not found|could not be found|not-found)|resolvectl: (command )?not found|stub file not found'
  [[ "$t" =~ $re ]] && { echo resolved_missing; return; }
  re='no .* asset found'
  [[ "$t" =~ $re ]] && { echo no_asset; return; }
  re='rate limit|http 403|403 forbidden|error: 403|error: 429'
  [[ "$t" =~ $re ]] && { echo ratelimit; return; }
  re='could not resolve host|name or service not known|timed out|timeout|connection refused|network is unreachable|temporary failure in name resolution|failed to connect|curl: \([0-9]+\)'
  [[ "$t" =~ $re ]] && { echo network; return; }
  re='permission denied|operation not permitted|must be run as root'
  [[ "$t" =~ $re ]] && { echo permission; return; }
  re='command not found|: not found|missing tool|no such file or directory'
  [[ "$t" =~ $re ]] && { echo missing_tool; return; }
  echo unknown
}

missing_tool_name() {  # <text>; prints the missing command name, if any
  local t="$1" re1='Missing tool: ([A-Za-z0-9_.+-]+)' re2='([A-Za-z0-9_.+-]+): (command )?not found'
  if [[ "$t" =~ $re1 ]]; then printf '%s' "${BASH_REMATCH[1]}"
  elif [[ "$t" =~ $re2 ]]; then printf '%s' "${BASH_REMATCH[1]}"
  fi
}

# present_problem <kind> <details>: shows the dialog; prints apply, alt or cancel.
present_problem() {
  local kind="$1" details="$2" choice="" prompt
  {
    printf '\n\033[1;33m== %s ==\033[0m\n' "$(msg "p_${kind}_t")"
    printf '%s\n  %s\n' "$(msg pd_what)" "$(msg "p_${kind}_e")"
    printf '%s\n  %s\n' "$(msg pd_prop)" "$(msg "p_${kind}_f")"
    printf '%s\n' "$(msg pd_details)"
    printf '%s\n' "$details" | tail -n 6 | sed 's/^/    /'
  } >&2
  if [[ "$kind" == "missing_resolvconf" ]]; then
    prompt="$(msg pd_choose_alt "$(msg p_missing_resolvconf_a)")"
  else
    prompt="$(msg pd_choose)"
  fi
  printf '%s' "$prompt" >&2
  read -r choice || choice=""
  case "${choice,,}" in
    a) echo apply ;;
    s) [[ "$kind" == "missing_resolvconf" ]] && echo alt || echo cancel ;;
    *) echo cancel ;;
  esac
}

rotate_arg_style() {
  case "$(setting_get SPOOF_ARG_STYLE)" in
    auto)   setting_set SPOOF_ARG_STYLE config ;;
    config) setting_set SPOOF_ARG_STYLE flags ;;
    flags)  setting_set SPOOF_ARG_STYLE port ;;
    port)   setting_set SPOOF_ARG_STYLE none ;;
    *)      setting_set SPOOF_ARG_STYLE auto ;;
  esac
  log "SpoofDPI argument style: $(setting_get SPOOF_ARG_STYLE)"
}

install_resolvconf() {
  case "$PM" in
    apt) pm_install resolvconf ;;
    *)   pm_install openresolv ;;
  esac
}

# apply_fix <kind> <alt 0|1> <details>: exits 0 to resume, 3 to stop.
apply_fix() {
  local kind="$1" alt="$2" details="$3" port new tool pkg other re
  case "$kind" in
    port_in_use)
      port="$(setting_get SPOOF_PORT)"
      new="$(find_free_port $(( port + 1 )))" || exit 3
      setting_set SPOOF_PORT "$new"
      log "$(msg port_switched "$new")" ;;
    unsupported_flag)
      rotate_arg_style ;;
    missing_resolvconf)
      if [[ "$alt" == "1" ]]; then
        setting_set WG_STRIP_DNS 1
      else
        install_resolvconf
        configure_dot
      fi ;;
    missing_tool)
      tool="$(missing_tool_name "$details")"
      case "$tool" in
        warp-cli) warp_install ;;
        wgcf) wg_install ;;
        spoofdpi|spoof-dpi) spoof_install ;;
        "") exit 3 ;;
        *) pkg="$(package_for_tool "$tool")"
           [[ -n "$pkg" ]] || exit 3
           pm_install "$pkg" ;;
      esac ;;
    permission)
      [[ "${EUID}" -eq 0 ]] || exit 3 ;;
    network)
      new=$(( $(setting_get NET_TIMEOUT) * 2 )); (( new > 120 )) && new=120
      setting_set NET_TIMEOUT "$new"
      sleep 3 ;;
    ratelimit)
      sleep 30 ;;
    resolved_missing)
      [[ "$PM" == "pacman" ]] || pm_install systemd-resolved || true
      systemctl enable --now systemd-resolved ;;
    conflict)
      re='conflict:(warp|wireguard)'
      if [[ "${details,,}" =~ $re ]]; then other="${BASH_REMATCH[1]}"; else exit 3; fi
      if [[ "$other" == "warp" ]]; then warp_stop; else wg_stop; fi ;;
    no_asset)
      settings_menu
      exit 3 ;;
    *) : ;;
  esac
  return 0
}

# guarded <function> [args...]: runs an operation with smart recovery.
guarded() {
  local rc kind choice details fixrc
  local -A tried=()
  while true; do
    : > "$ERR_LOG"
    ( set -e; "$@" ) 2>&1 | tee -a "$ERR_LOG"
    rc="${PIPESTATUS[0]}"
    (( rc == 0 )) && return 0

    details="$(cat "$ERR_LOG")"
    kind="$(classify_problem "$details")"
    tried[$kind]=$(( ${tried[$kind]:-0} + 1 ))
    if (( ${tried[$kind]} > 3 )); then warn "$(msg giving_up)"; return 1; fi

    choice="$(present_problem "$kind" "$details")"
    if [[ "$choice" == "cancel" ]]; then warn "$(msg cancelled)"; return 1; fi

    ( set -e; apply_fix "$kind" "$([[ "$choice" == "alt" ]] && echo 1 || echo 0)" "$details" ) 2>&1 | tee -a "$ERR_LOG"
    fixrc="${PIPESTATUS[0]}"
    if (( fixrc == 3 )); then warn "$(msg cancelled)"; return 1; fi
    if (( fixrc != 0 )); then warn "$(msg fix_failed)"; return 1; fi
    log "$(msg fix_applied)"
  done
}

# -----------------------------------------------------------------------------
# Backups: every original is recorded once and never overwritten.
# -----------------------------------------------------------------------------
snapshot_file() {  # <path> <key>
  local path="$1" key="$2" base="${BACKUP_DIR}/$2"
  if [[ -e "${base}.file" || -e "${base}.link" || -e "${base}.absent" ]]; then
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

has_user_bus() { [[ -S "/run/user/$(id -u "$1")/bus" ]]; }

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
    schema="${entry% *}"; key="${entry##* }"
    value="$(user_gsettings "$user" get "$schema" "$key" 2>/dev/null || true)"
    printf '%s\t%s\t%s\n' "$schema" "$key" "$value" >> "$out"
  done
  return 0
}

backup_state() {
  [[ "$(state_get BACKUP_DONE)" == "1" ]] && return 0
  mkdir -p "$BACKUP_DIR"
  chmod 0700 "$STATE_DIR"
  snapshot_file "$RESOLVED_CONF" resolved.conf
  snapshot_file "$RESOLV_CONF" resolv.conf
  snapshot_file "$ENV_FILE" environment
  if [[ ! -f "$USERS_FILE" ]]; then
    awk -F: '$3 >= 1000 && $3 < 65534 && $6 ~ /^\/home\// {printf "%s\t%s\n", $1, $6}' /etc/passwd > "$USERS_FILE"
  fi
  local user home
  while IFS=$'\t' read -r user home; do
    [[ -n "$user" ]] || continue
    if has_user_bus "$user" && command -v gsettings >/dev/null 2>&1; then snapshot_gnome "$user"; fi
    if command -v kwriteconfig6 >/dev/null 2>&1 || command -v kwriteconfig5 >/dev/null 2>&1; then
      snapshot_file "${home}/.config/kioslaverc" "kde-${user}"
    fi
  done < "$USERS_FILE"
  state_set BACKUP_DONE 1
  log "Original network and proxy settings backed up to ${BACKUP_DIR}"
}

# -----------------------------------------------------------------------------
# Encrypted DNS (DNS-over-TLS) with leak protection
# -----------------------------------------------------------------------------
configure_dot() {
  command -v resolvectl >/dev/null 2>&1 || die "resolvectl: command not found (systemd-resolved is missing)"
  systemctl enable --now systemd-resolved >/dev/null 2>&1 || die "systemd-resolved could not be enabled (not found or failed)"
  cat > "$RESOLVED_CONF" <<EOF
# Managed by Security DNS. The original file is restored by the undo option.
[Resolve]
DNS=$(setting_get DNS_SERVERS)
FallbackDNS=
DNSOverTLS=yes
DNSSEC=allow-downgrade
Domains=~.
EOF
  [[ -f "$STUB_RESOLV" ]] || die "systemd-resolved stub file not found at ${STUB_RESOLV}"
  ln -sf "$STUB_RESOLV" "$RESOLV_CONF"
  systemctl restart systemd-resolved
  if resolvectl query one.one.one.one >/dev/null 2>&1; then
    log "Encrypted DNS works ($(setting_get DNS_SERVERS))."
  else
    warn "Test DNS query failed. Inspect with: resolvectl status"
  fi
}

ensure_encrypted_dns() {
  if grep -q 'Managed by Security DNS' "$RESOLVED_CONF" 2>/dev/null; then return 0; fi
  configure_dot
}

# Backup + encrypted DNS. Called before any tool starts.
ensure_prepared() {
  backup_state
  ensure_encrypted_dns
}

# -----------------------------------------------------------------------------
# System and desktop proxy (used while SpoofDPI runs)
# -----------------------------------------------------------------------------
write_env_proxy() {  # <port or empty to disable>
  local port="$1" tmp
  tmp="$(mktemp)"
  if [[ -f "$ENV_FILE" ]]; then
    sed '/^# BEGIN security-dns$/,/^# END security-dns$/d' "$ENV_FILE" > "$tmp"
  else
    : > "$tmp"
  fi
  if [[ -n "$port" ]]; then
    {
      cat "$tmp"
      echo "# BEGIN security-dns"
      echo "http_proxy=http://127.0.0.1:${port}"
      echo "https_proxy=http://127.0.0.1:${port}"
      echo "HTTP_PROXY=http://127.0.0.1:${port}"
      echo "HTTPS_PROXY=http://127.0.0.1:${port}"
      echo "no_proxy=localhost,127.0.0.1,::1"
      echo "NO_PROXY=localhost,127.0.0.1,::1"
      echo "# END security-dns"
    } > "${tmp}.new"
    cat "${tmp}.new" > "$ENV_FILE"
    rm -f "${tmp}.new"
  else
    cat "$tmp" > "$ENV_FILE"
  fi
  rm -f "$tmp"
}

set_gnome_proxy() {  # <port or empty>
  local port="$1" user home
  command -v gsettings >/dev/null 2>&1 || return 0
  [[ -f "$USERS_FILE" ]] || return 0
  while IFS=$'\t' read -r user home; do
    [[ -n "$user" ]] || continue
    has_user_bus "$user" || continue
    if [[ -n "$port" ]]; then
      user_gsettings "$user" set org.gnome.system.proxy mode 'manual' || true
      user_gsettings "$user" set org.gnome.system.proxy.http host '127.0.0.1' || true
      user_gsettings "$user" set org.gnome.system.proxy.http port "$port" || true
      user_gsettings "$user" set org.gnome.system.proxy.https host '127.0.0.1' || true
      user_gsettings "$user" set org.gnome.system.proxy.https port "$port" || true
      user_gsettings "$user" set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']" || true
    else
      user_gsettings "$user" set org.gnome.system.proxy mode 'none' || true
    fi
  done < "$USERS_FILE"
  return 0
}

set_kde_proxy() {  # <port or empty>
  local port="$1" user home kw
  kw="$(command -v kwriteconfig6 || command -v kwriteconfig5 || true)"
  [[ -n "$kw" && -f "$USERS_FILE" ]] || return 0
  while IFS=$'\t' read -r user home; do
    [[ -n "$user" ]] || continue
    if [[ -n "$port" ]]; then
      local k
      for k in "ProxyType 1" "httpProxy http://127.0.0.1:${port}" "httpsProxy http://127.0.0.1:${port}" "NoProxyFor localhost,127.0.0.0/8,::1"; do
        runuser -u "$user" -- "$kw" --file kioslaverc --group "Proxy Settings" --key "${k%% *}" "${k#* }" </dev/null || true
      done
    else
      runuser -u "$user" -- "$kw" --file kioslaverc --group "Proxy Settings" --key ProxyType 0 </dev/null || true
    fi
  done < "$USERS_FILE"
  return 0
}

set_system_proxy() { write_env_proxy "$1"; set_gnome_proxy "$1"; set_kde_proxy "$1"; }

# -----------------------------------------------------------------------------
# Tool 1: SpoofDPI
# -----------------------------------------------------------------------------
resolve_spoofdpi_release() {
  local json urls
  json="$(http_get "https://api.github.com/repos/${SPOOFDPI_REPO}/releases/latest")" \
    || die "Could not query the GitHub API for ${SPOOFDPI_REPO} (network issue or rate limit)."
  RELEASE_TAG="$(printf '%s' "$json" | grep -o '"tag_name": *"[^"]*"' | head -n1 | sed 's/.*"\([^"]*\)"$/\1/' || true)"
  urls="$(printf '%s' "$json" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(https[^"]*\)"$/\1/' || true)"
  ASSET_URL="$(printf '%s\n' "$urls" | grep -iE 'linux' | grep -iE 'amd64|x86_64' | grep -viE '\.(sha256|sig|asc|txt|md5)$' | head -n1 || true)"
  SUMS_URL="$(printf '%s\n' "$urls" | grep -iE 'sha256|checksum' | grep -viE 'windows|darwin|arm' | head -n1 || true)"
  [[ -n "$ASSET_URL" ]] || die "No linux-amd64 asset found in SpoofDPI release ${RELEASE_TAG:-unknown}."
}

verify_checksum() {  # <file> <sums file> <asset name>
  local file="$1" sums="$2" name="$3" expected actual
  expected="$(awk -v n="$name" 'index($0, n) {print $1; exit}' "$sums" || true)"
  [[ -n "$expected" ]] || expected="$(awk 'NF {print $1; exit}' "$sums" || true)"
  expected="$(printf '%s' "$expected" | tr -d '[:space:]')"
  if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
    warn "Checksum file could not be parsed; skipping verification."
    return 0
  fi
  actual="$(sha256sum "$file" | awk '{print $1}')"
  [[ "${expected,,}" == "${actual,,}" ]] || die "SHA-256 mismatch for ${name}. Refusing to install (checksum error)."
  log "SHA-256 checksum verified."
}

spoof_installed() { [[ -x "$(spoof_bin)" ]]; }
spoof_running()   { systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; }
spoof_enabled()   { systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; }

spoof_install() {
  if [[ -n "$(setting_get SPOOF_PATH)" && -x "$(setting_get SPOOF_PATH)" ]]; then
    log "Using your own SpoofDPI program: $(setting_get SPOOF_PATH)"
    return 0
  fi
  resolve_spoofdpi_release
  if [[ "$RELEASE_TAG" == "$(state_get SPOOFDPI_TAG)" && -x "$SPOOF_BIN_DEFAULT" ]]; then
    log "SpoofDPI is up to date (${RELEASE_TAG})."
    return 0
  fi
  TMP_DIR="$(mktemp -d)"
  local name file bin=""
  name="$(basename "$ASSET_URL")"
  file="${TMP_DIR}/${name}"
  log "Downloading SpoofDPI ${RELEASE_TAG} (${name})"
  http_get "$ASSET_URL" "$file"
  if [[ -n "$SUMS_URL" ]] && http_get "$SUMS_URL" "${TMP_DIR}/checksums" 2>/dev/null; then
    verify_checksum "$file" "${TMP_DIR}/checksums" "$name"
  else
    warn "No checksum published for this release; integrity was not verified."
  fi
  case "$name" in
    *.tar.gz|*.tgz)
      mkdir -p "${TMP_DIR}/extract"
      tar -xzf "$file" -C "${TMP_DIR}/extract"
      bin="$(find "${TMP_DIR}/extract" -type f \( -name 'spoofdpi' -o -name 'spoof-dpi' \) | head -n1 || true)" ;;
    *) bin="$file" ;;
  esac
  [[ -n "$bin" && -f "$bin" ]] || die "Could not locate the spoofdpi binary inside ${name}."
  install -m 0755 "$bin" "$SPOOF_BIN_DEFAULT"
  state_set SPOOFDPI_TAG "$RELEASE_TAG"
  log "Installed SpoofDPI ${RELEASE_TAG}"
}

# Reads --help to learn how the installed build takes its address and port.
# Prints: config, flags, port or none.
spoofdpi_port_control() {
  local style help
  style="$(setting_get SPOOF_ARG_STYLE)"
  if [[ "$style" != "auto" ]]; then printf '%s' "$style"; return 0; fi
  help="$("$(spoof_bin)" --help 2>&1 || true)"
  if grep -qE '(^|[[:space:]])-config([[:space:]=]|$)' <<< "$help"; then echo config
  elif grep -qE '(^|[[:space:]])-addr([[:space:]=]|$)' <<< "$help" && grep -qE '(^|[[:space:]])-port([[:space:]=]|$)' <<< "$help"; then echo flags
  elif grep -qE '(^|[[:space:]])-port([[:space:]=]|$)' <<< "$help"; then echo port
  else echo none
  fi
}

# The port SpoofDPI will really use: builds without a port option are fixed to 8080.
spoof_effective_port() {
  if [[ "$(spoofdpi_port_control)" == "none" ]]; then printf '8080'; else setting_get SPOOF_PORT; fi
}

build_spoofdpi_args() {  # <port>
  local port="$1" style args="" help
  style="$(spoofdpi_port_control)"
  case "$style" in
    config)
      mkdir -p "$LIB_DIR"
      printf '[app]\nlisten-addr = "127.0.0.1:%s"\n' "$port" > "$SPOOF_CONFIG"
      args="--config ${SPOOF_CONFIG}" ;;
    flags) args="--addr 127.0.0.1 --port ${port}" ;;
    port)  args="--port ${port}" ;;
    *)     args="" ;;
  esac
  help="$("$(spoof_bin)" --help 2>&1 || true)"
  if grep -qE '(^|[[:space:]])-system-proxy([[:space:]=]|$)' <<< "$help"; then
    args="${args:+$args }--system-proxy=false"
  fi
  [[ -z "$(setting_get SPOOF_EXTRA_FLAGS)" ]] || args="${args:+$args }$(setting_get SPOOF_EXTRA_FLAGS)"
  printf '%s' "$args"
}

write_service() {  # <port>
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Security DNS - SpoofDPI local DPI-bypass proxy
Documentation=https://github.com/arcalc/setup_privacy
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(spoof_bin) $(build_spoofdpi_args "$1")
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
  systemctl daemon-reload
}

ensure_port_free() {  # <port>
  local port="$1" new
  if ! port_in_use "$port"; then return 0; fi
  if [[ "$(spoofdpi_port_control)" == "none" ]]; then
    die "This SpoofDPI build cannot change its port, and port ${port} is occupied. Free that port and try again."
  fi
  warn "$(msg port_busy "$port")"
  new="$(find_free_port $(( port + 1 )))" || die "No free port was found near ${port}."
  setting_set SPOOF_PORT "$new"
  log "$(msg port_switched "$new")"
}

preflight_spoofdpi() {  # <port>
  local port="$1" log_file rc=0
  local -a argv=()
  log_file="$(mktemp)"
  read -ra argv <<< "$(build_spoofdpi_args "$port")"
  timeout 4 "$(spoof_bin)" "${argv[@]}" >"$log_file" 2>&1 || rc=$?
  if [[ "$rc" -eq 124 ]]; then rm -f "$log_file"; log "$(msg preflight_ok)"; return 0; fi
  warn "$(msg preflight_fail "$rc")"
  cat "$log_file" >&2
  rm -f "$log_file"
  return 1
}

start_and_verify() {  # <port>
  local port="$1" attempt
  systemctl restart "$SERVICE_NAME" || true
  sleep 2
  for attempt in $(seq 1 15); do
    if port_in_use "$port" && systemctl is-active --quiet "$SERVICE_NAME"; then
      log "$(msg start_ok "$port")"
      return 0
    fi
    sleep 1
  done
  warn "$(msg start_fail)"
  journalctl -u "$SERVICE_NAME" -n 40 --no-pager 2>&1 >&2 || true
  return 1
}

spoof_start() {
  spoof_installed || die "SpoofDPI: command not found (not installed)"
  ensure_prepared
  systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
  local port
  port="$(spoof_effective_port)"
  ensure_port_free "$port"
  port="$(spoof_effective_port)"
  write_service "$port"
  preflight_spoofdpi "$port"
  start_and_verify "$port"
  set_system_proxy "$port"
}

spoof_stop() {
  set_system_proxy ""
  systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
  return 0
}

spoof_enable() {
  spoof_installed || die "SpoofDPI: command not found (not installed)"
  [[ -f "$SERVICE_FILE" ]] || write_service "$(spoof_effective_port)"
  systemctl enable "$SERVICE_NAME"
}

spoof_disable() { systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true; }

spoof_uninstall() {
  spoof_stop
  bash "$UNINSTALL_PATH" --tool spoofdpi
}

# -----------------------------------------------------------------------------
# Tool 2: Cloudflare WARP
# -----------------------------------------------------------------------------
warp_cli() { warp-cli --accept-tos "$@"; }

warp_installed() { command -v warp-cli >/dev/null 2>&1; }
warp_running()   { warp_installed && warp_cli status 2>/dev/null | grep -qi 'status update: connected'; }
warp_enabled()   { systemctl is-enabled --quiet warp-svc 2>/dev/null; }

warp_install() {
  if warp_installed; then
    log "Cloudflare WARP client is already installed; it will be left in place on uninstall."
    return 0
  fi
  case "$PM" in
    apt)
      command -v gpg >/dev/null 2>&1 || pm_install gnupg
      # shellcheck source=/dev/null
      . /etc/os-release
      local codename="${VERSION_CODENAME:-}"
      [[ -n "$codename" ]] || die "Could not detect the release codename for the Cloudflare WARP repository."
      [[ -f "$WARP_APT_KEY" ]] || state_set WARP_KEY_ADDED 1
      [[ -f "$WARP_APT_LIST" ]] || state_set WARP_REPO_ADDED 1
      http_get "$WARP_APT_KEY_URL" | gpg --yes --dearmor --output "$WARP_APT_KEY"
      echo "deb [signed-by=${WARP_APT_KEY}] https://pkg.cloudflareclient.com/ ${codename} main" > "$WARP_APT_LIST"
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      state_set WARP_PKG_ADDED 1
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cloudflare-warp ;;
    dnf)
      [[ -f "$WARP_DNF_REPO" ]] || state_set WARP_REPO_ADDED 1
      http_get "$WARP_DNF_URL" "$WARP_DNF_REPO"
      state_set WARP_PKG_ADDED 1
      dnf install -y -q cloudflare-warp ;;
    *) die "WARP needs an apt or dnf based system (no_asset: no WARP package found for this system)." ;;
  esac
  warp_installed || die "warp-cli: command not found after installation"
  log "Cloudflare WARP client installed."
}

warp_start() {
  warp_installed || die "warp-cli: command not found (not installed)"
  if wg_running; then die "CONFLICT:wireguard - WireGuard is running; WARP cannot start at the same time."; fi
  ensure_prepared
  if ! systemctl is-enabled --quiet warp-svc 2>/dev/null; then state_set WARP_SVC_ENABLED_BY_US 1; fi
  systemctl start warp-svc
  sleep 3
  if ! warp_cli registration show >/dev/null 2>&1; then
    warp_cli registration new || die "Could not register the WARP client."
    state_set WARP_REGISTERED_BY_US 1
  fi
  warp_cli connect >/dev/null 2>&1 || true
  local i
  for i in $(seq 1 20); do
    if warp_running; then log "Cloudflare WARP is connected."; return 0; fi
    sleep 1
  done
  die "WARP did not report Connected (connection timed out). Check: warp-cli status"
}

warp_stop() {
  if warp_installed; then warp_cli disconnect >/dev/null 2>&1 || true; fi
  return 0
}

warp_enable()  { warp_installed || die "warp-cli: command not found (not installed)"; systemctl enable warp-svc; }
warp_disable() { systemctl disable warp-svc >/dev/null 2>&1 || true; }

warp_uninstall() {
  warp_stop
  bash "$UNINSTALL_PATH" --tool warp
}

# -----------------------------------------------------------------------------
# Tool 3: WireGuard with a WARP profile made by wgcf
# -----------------------------------------------------------------------------
wg_installed() { command -v wg-quick >/dev/null 2>&1 && [[ -f "$WG_CONF" ]]; }
wg_running()   { command -v wg >/dev/null 2>&1 && wg show "$WG_IFACE" >/dev/null 2>&1; }
wg_enabled()   { systemctl is-enabled --quiet "$WG_SERVICE" 2>/dev/null; }

install_wireguard_tools() {
  command -v wg-quick >/dev/null 2>&1 && return 0
  state_set WG_TOOLS_ADDED 1
  pm_install wireguard-tools
  command -v wg-quick >/dev/null 2>&1 || die "wg-quick: command not found after installation"
}

install_wgcf() {
  if [[ -n "$(setting_get WGCF_PATH)" && -x "$(setting_get WGCF_PATH)" ]]; then return 0; fi
  local json tag url tmp
  json="$(http_get "https://api.github.com/repos/${WGCF_REPO}/releases/latest")" \
    || die "Could not query the GitHub API for ${WGCF_REPO}."
  tag="$(printf '%s' "$json" | grep -o '"tag_name": *"[^"]*"' | head -n1 | sed 's/.*"\([^"]*\)"$/\1/' || true)"
  url="$(printf '%s' "$json" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(https[^"]*\)"$/\1/' | grep -E 'linux_amd64$' | head -n1 || true)"
  if [[ -x "$WGCF_BIN_DEFAULT" && "$tag" == "$(state_get WGCF_TAG)" ]]; then
    log "wgcf is up to date (${tag})."; return 0
  fi
  [[ -n "$url" ]] || die "No linux_amd64 wgcf asset found in release ${tag:-unknown}."
  [[ -x "$WGCF_BIN_DEFAULT" ]] || state_set WGCF_BIN_ADDED 1
  tmp="$(mktemp)"
  http_get "$url" "$tmp"
  install -m 0755 "$tmp" "$WGCF_BIN_DEFAULT"
  rm -f "$tmp"
  state_set WGCF_TAG "$tag"
  log "Installed wgcf ${tag}"
}

# Builds the active profile from the wgcf profile plus your Settings.
apply_wg_settings() {
  local src="${WGCF_DIR}/wgcf-profile.conf" ep strip tmp
  [[ -f "$src" ]] || die "WireGuard profile is missing: ${src}"
  ep="$(setting_get WG_ENDPOINT)"
  strip="$(setting_get WG_STRIP_DNS)"
  tmp="$(mktemp)"
  cp "$src" "$tmp"
  [[ "$strip" == "1" ]] && sed -i '/^DNS[[:space:]]*=/d' "$tmp"
  [[ -z "$ep" ]] || sed -i "s|^Endpoint[[:space:]]*=.*|Endpoint = ${ep}|" "$tmp"
  mkdir -p "$(dirname "$WG_CONF")"
  install -m 0600 "$tmp" "$WG_CONF"
  rm -f "$tmp"
  state_set WG_CONF_ADDED 1
}

wg_install() {
  install_wireguard_tools
  install_wgcf
  mkdir -p "$WGCF_DIR"
  chmod 0700 "$WGCF_DIR"
  if [[ ! -f "${WGCF_DIR}/wgcf-profile.conf" ]]; then
    ( cd "$WGCF_DIR" || exit 1
      [[ -f wgcf-account.toml ]] || "$(wgcf_bin)" register --accept-tos
      "$(wgcf_bin)" generate )
  fi
  apply_wg_settings
  log "WireGuard profile ready at ${WG_CONF}"
}

wg_start() {
  wg_installed || die "wg-quick: command not found (WireGuard is not installed)"
  if warp_running; then die "CONFLICT:warp - WARP is connected; WireGuard cannot start at the same time."; fi
  ensure_prepared
  wg_running && wg-quick down "$WG_IFACE" >/dev/null 2>&1 || true
  apply_wg_settings
  wg-quick up "$WG_IFACE"
  log "WireGuard tunnel is up."
}

wg_stop() {
  if command -v wg-quick >/dev/null 2>&1 && wg_running; then
    wg-quick down "$WG_IFACE" >/dev/null 2>&1 || true
  fi
  return 0
}

wg_enable()  { wg_installed || die "wg-quick: command not found (not installed)"; systemctl enable "$WG_SERVICE"; }
wg_disable() { systemctl disable "$WG_SERVICE" >/dev/null 2>&1 || true; }

wg_uninstall() {
  wg_stop
  wg_disable
  bash "$UNINSTALL_PATH" --tool wireguard
}

# -----------------------------------------------------------------------------
# Tool dispatcher, quick modes, kill switch, restore
# -----------------------------------------------------------------------------
tool_prefix() {
  case "$1" in spoofdpi) echo spoof ;; warp) echo warp ;; wireguard) echo wg ;; esac
}

tool_do() {  # <tool> <action>
  local p; p="$(tool_prefix "$1")"
  "${p}_$2"
}

# Quick mode: start one tool, stop the others (installing it first if needed).
preset_apply() {  # <1|2|3>
  case "$1" in
    1) wg_stop; warp_stop; spoof_installed || spoof_install; spoof_start ;;
    2) spoof_stop; wg_stop; warp_installed || warp_install; warp_start ;;
    3) spoof_stop; warp_stop; wg_installed || wg_install; wg_start ;;
  esac
}

confirm_tunnel() {
  printf '\n%s\n\n' "$(msg tunnel_warn)"
  confirm "$(msg continue_q)"
}

# Stops every tool at once. Best effort, no prompts, so it is fast and reliable.
kill_switch() {
  local failed=0
  step "$(msg kill_start)"
  set_system_proxy "" || failed=1
  wg_stop || failed=1
  warp_stop || failed=1
  systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
  if spoof_running || warp_running || wg_running; then failed=1; fi
  ensure_encrypted_dns || failed=1
  if (( failed == 0 )); then log "$(msg kill_done)"; else warn "$(msg kill_partial)"; fi
  return 0
}

run_restore_original() {
  [[ -f "$UNINSTALL_PATH" ]] || { warn "$(msg restore_fail)"; return 0; }
  if confirm "$(msg restore_q)"; then
    if bash "$UNINSTALL_PATH" --restore-only; then log "$(msg restore_done)"; else warn "$(msg restore_fail)"; fi
  fi
}

run_uninstaller() {
  if [[ -f "$UNINSTALL_PATH" ]]; then exec bash "$UNINSTALL_PATH"; fi
  TMP_DIR="$(mktemp -d)"
  http_get "${REPO_RAW}/uninstall.sh" "${TMP_DIR}/uninstall.sh" || die "Could not download uninstall.sh."
  exec bash "${TMP_DIR}/uninstall.sh"
}

# -----------------------------------------------------------------------------
# Status
# -----------------------------------------------------------------------------
tool_status_line() {  # <tool> <label>
  local p parts=()
  p="$(tool_prefix "$1")"
  if "${p}_installed"; then
    parts+=("$(msg st_installed)")
    if "${p}_running"; then parts+=("$(msg st_running)"); else parts+=("$(msg st_stopped)"); fi
    if "${p}_enabled"; then parts+=("$(msg st_enabled)"); else parts+=("$(msg st_disabled)"); fi
  else
    parts+=("$(msg st_missing)")
  fi
  local IFS=', '
  printf '  %-12s : %s\n' "$2" "${parts[*]}"
}

show_status() {
  local dns
  dns="$(grep -q 'Managed by Security DNS' "$RESOLVED_CONF" 2>/dev/null && echo "DNS-over-TLS ($(setting_get DNS_SERVERS))" || echo "-")"
  printf '\n'
  tool_status_line spoofdpi "SpoofDPI"
  tool_status_line warp "WARP"
  tool_status_line wireguard "WireGuard"
  printf '  %-12s : %s\n\n' "$(msg stat_dns)" "$dns"
}

# -----------------------------------------------------------------------------
# Updates
# -----------------------------------------------------------------------------
check_updates() {
  step "Security DNS script"
  local remote=""
  remote="$(http_get "${REPO_RAW}/install.sh" 2>/dev/null | sed -n 's/^readonly SCRIPT_VERSION="\(.*\)"$/\1/p' | head -n1 || true)"
  if [[ -z "$remote" ]]; then
    warn "Could not read the remote script version."
  elif [[ "$remote" != "$SCRIPT_VERSION" ]]; then
    if confirm "Update the script from ${SCRIPT_VERSION} to ${remote}?"; then
      TMP_DIR="$(mktemp -d)"
      http_get "${REPO_RAW}/install.sh" "${TMP_DIR}/install.sh"
      http_get "${REPO_RAW}/uninstall.sh" "${TMP_DIR}/uninstall.sh"
      if bash -n "${TMP_DIR}/install.sh" && bash -n "${TMP_DIR}/uninstall.sh"; then
        install -m 0755 "${TMP_DIR}/install.sh" "$APP_BIN"
        install -m 0755 "${TMP_DIR}/uninstall.sh" "$UNINSTALL_PATH"
        log "Script updated to ${remote}. Reopen the menu to use it."
      else
        warn "Downloaded scripts failed the syntax check; keeping the current version."
      fi
    fi
  else
    log "Script is up to date (${SCRIPT_VERSION})."
  fi

  if spoof_installed; then
    step "SpoofDPI"
    guarded spoof_install && { spoof_running && guarded spoof_start; }
  fi
  if warp_installed; then
    step "Cloudflare WARP"
    case "$PM" in
      apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade cloudflare-warp >/dev/null 2>&1 && log "WARP client is up to date." || warn "Could not upgrade the WARP client." ;;
      dnf) dnf upgrade -y -q cloudflare-warp >/dev/null 2>&1 && log "WARP client is up to date." || warn "Could not upgrade the WARP client." ;;
    esac
  fi
  if [[ -x "$(wgcf_bin)" ]]; then step "wgcf"; guarded install_wgcf; fi
}

# -----------------------------------------------------------------------------
# Application install (first run)
# -----------------------------------------------------------------------------
install_launcher() {
  mkdir -p "$LIB_DIR"
  local self="${BASH_SOURCE[0]:-}" self_real="" dir
  [[ -n "$self" && -f "$self" ]] && self_real="$(readlink -f "$self")"
  if [[ -n "$self_real" && "$self_real" != "$APP_BIN" ]]; then
    install -m 0755 "$self_real" "$APP_BIN"
  elif [[ -z "$self_real" ]]; then
    TMP_DIR="$(mktemp -d)"
    http_get "${REPO_RAW}/install.sh" "${TMP_DIR}/install.sh"
    install -m 0755 "${TMP_DIR}/install.sh" "$APP_BIN"
  fi
  dir="$(dirname "${self_real:-/nonexistent}")"
  if [[ -f "${dir}/uninstall.sh" ]]; then
    install -m 0755 "${dir}/uninstall.sh" "$UNINSTALL_PATH"
  else
    TMP_DIR="$(mktemp -d)"
    http_get "${REPO_RAW}/uninstall.sh" "${TMP_DIR}/uninstall.sh"
    install -m 0755 "${TMP_DIR}/uninstall.sh" "$UNINSTALL_PATH"
  fi
  mkdir -p "$(dirname "$DESKTOP_FILE")"
  cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Security DNS
Comment=Encrypted DNS, DPI bypass, and VPN-like tools
Exec=x-terminal-emulator -e sudo ${APP_BIN}
Icon=network-vpn
Terminal=false
Categories=Network;Security;
EOF
  chmod 0644 "$DESKTOP_FILE"
  log "Installed ${APP_BIN}, the uninstaller, and the desktop entry."
}

install_all() {
  require_root
  check_platform
  detect_package_manager
  printf '%s\n' "$(msg first_run)"
  step "Checking dependencies"
  install_base_packages
  step "Installing the Security DNS application"
  install_launcher
  state_set INSTALLED 1
  step "Backing up your settings and enabling encrypted DNS"
  guarded ensure_prepared
  printf '\n\033[1;32m%s\033[0m\n  %s\n  %s\n\n' "$(msg done_title)" "$(msg done_menu)" "$(msg done_next)"
  if confirm "$(msg first_start_q)"; then
    guarded preset_apply 1
  fi
}

# -----------------------------------------------------------------------------
# Menus
# -----------------------------------------------------------------------------
show_about() {
  printf '\n\033[1m%s\033[0m  v%s\n\n' "$(msg about_head)" "$SCRIPT_VERSION"
  printf '  %s\n' "$(msg about_dev "$PORTFOLIO_URL")" "$(msg about_mail "$CONTACT_EMAIL")" "$(msg about_license)"
  printf '\n  \033[1m%s\033[0m\n  %s\n\n' "$(msg about_sec_title)" "$(msg about_sec_text "$CONTACT_EMAIL")"
  pause
}

settings_menu() {
  local choice key idx new current
  while true; do
    printf '\n\033[1m%s\033[0m\n  %s\n\n' "$(msg set_head)" "$(msg set_hint)"
    idx=1
    for key in "${SETTING_KEYS[@]}"; do
      current="$(setting_get "$key")"
      [[ "$key" == "GITHUB_TOKEN" && -n "$current" ]] && current="********"
      printf '  %2d) %s\n      %s: %s\n' "$idx" "$(msg "set_${key}")" "$(msg set_current)" "${current:-<empty>}"
      idx=$(( idx + 1 ))
    done
    printf '\n'
    read -r -p "$(msg choose)" choice || return 0
    case "${choice,,}" in
      b|q|"") return 0 ;;
      r) if confirm "$(msg set_reset_q)"; then rm -f "$SETTINGS_FILE"; log "$(msg set_saved)"; fi ;;
      *)
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#SETTING_KEYS[@]} )); then
          key="${SETTING_KEYS[$(( choice - 1 ))]}"
          read -r -p "$(msg set_prompt)" new || new=""
          if [[ -z "$new" ]]; then continue; fi
          [[ "$new" == "-" ]] && new=""
          if setting_valid "$key" "$new"; then
            setting_set "$key" "$new"
            log "$(msg set_saved)"
            if [[ "$key" == "DNS_SERVERS" && "$(state_get INSTALLED)" == "1" ]]; then guarded configure_dot; fi
          else
            warn "$(msg set_invalid)"
          fi
        else
          warn "$(msg bad_choice)"
        fi ;;
    esac
  done
}

tool_menu() {  # <tool> <label>
  local tool="$1" label="$2" choice
  while true; do
    printf '\n\033[1m%s\033[0m\n  %s\n' "$label" "$(msg "tool_${tool}")"
    tool_status_line "$tool" "$label"
    printf '  %s\n' "$(msg act_install)" "$(msg act_start)" "$(msg act_stop)" "$(msg act_enable)" "$(msg act_disable)" "$(msg act_uninstall)" "$(msg tm_back)"
    printf '\n'
    read -r -p "$(msg choose)" choice || return 0
    case "${choice,,}" in
      1) guarded tool_do "$tool" install && log "$(msg done_ok)" ;;
      2) if [[ "$tool" == "spoofdpi" ]] || confirm_tunnel; then guarded tool_do "$tool" start && log "$(msg done_ok)"; fi ;;
      3) guarded tool_do "$tool" stop && log "$(msg done_ok)" ;;
      4) guarded tool_do "$tool" enable && log "$(msg done_ok)" ;;
      5) guarded tool_do "$tool" disable && log "$(msg done_ok)" ;;
      6) if confirm "$(msg continue_q)"; then guarded tool_do "$tool" uninstall && log "$(msg done_ok)"; fi ;;
      b|q|"") return 0 ;;
      *) warn "$(msg bad_choice)" ;;
    esac
  done
}

install_all_missing() {
  spoof_installed || guarded spoof_install
  warp_installed  || guarded warp_install
  wg_installed    || guarded wg_install
}

tool_manager_menu() {
  local choice
  while true; do
    printf '\n\033[1m%s\033[0m\n  %s\n\n' "$(msg tm_head)" "$(msg tm_hint)"
    show_status
    printf '  1) SpoofDPI\n  2) Cloudflare WARP\n  3) WireGuard (wgcf)\n  %s\n  %s\n  %s\n\n' "$(msg tm_all)" "$(msg tm_kill)" "$(msg tm_back)"
    read -r -p "$(msg choose)" choice || return 0
    case "${choice,,}" in
      1) tool_menu spoofdpi "SpoofDPI" ;;
      2) tool_menu warp "Cloudflare WARP" ;;
      3) tool_menu wireguard "WireGuard (wgcf)" ;;
      i) install_all_missing ;;
      k) kill_switch ;;
      b|q|"") return 0 ;;
      *) warn "$(msg bad_choice)" ;;
    esac
  done
}

print_menu() {
  printf '\n\033[1m%s\033[0m\n\n  %s\n  %s\n  %s\n  %s\n\n  %s\n' \
    "$(msg menu_head "$SCRIPT_VERSION")" "$(msg menu_quick)" "$(msg menu_1)" "$(msg menu_2)" "$(msg menu_3)" "$(msg menu_manage)"
  printf '  %s\n' "$(msg menu_4)" "$(msg menu_5)" "$(msg menu_6)" "$(msg menu_7)" "$(msg menu_8)" "$(msg menu_9)" "$(msg menu_a)" "$(msg menu_u)" "$(msg menu_q)"
  printf '\n'
}

run_menu() {
  require_root
  reconnect_terminal
  local choice
  while true; do
    print_menu
    read -r -p "$(msg choose)" choice || return 0
    case "${choice,,}" in
      1) guarded preset_apply 1 && log "$(msg done_ok)" ;;
      2) if confirm_tunnel; then guarded preset_apply 2 && log "$(msg done_ok)"; fi ;;
      3) if confirm_tunnel; then guarded preset_apply 3 && log "$(msg done_ok)"; fi ;;
      4) tool_manager_menu ;;
      5) settings_menu ;;
      6) show_status ;;
      7) check_updates ;;
      8) run_restore_original ;;
      9) kill_switch ;;
      a) show_about ;;
      u) if confirm "$(msg uninst_q)"; then run_uninstaller; fi ;;
      q) return 0 ;;
      *) warn "$(msg bad_choice)" ;;
    esac
  done
}

usage() {
  cat <<EOF
Security DNS - Linux CLI (version ${SCRIPT_VERSION})

Usage:
  sudo security-dns             open the menu (installs on the first run)
  sudo security-dns --menu      open the menu
  sudo security-dns --kill      kill switch: stop every tool, keep encrypted DNS
  sudo security-dns --restore   restore original settings, keep app and tools
  sudo security-dns --update    check for updates
  sudo security-dns --uninstall remove everything and restore your settings
  security-dns --version | --help

Developer : ${PORTFOLIO_URL}
Security  : ${CONTACT_EMAIL} (report vulnerabilities privately, never as public issues)
EOF
}

main() {
  ERR_LOG="$(mktemp)"
  detect_package_manager
  case "${1:-}" in
    --version) echo "$SCRIPT_VERSION" ;;
    -h|--help) usage ;;
    --kill)    require_root; UI_LANG="en"; kill_switch ;;
    --restore) require_root; UI_LANG="en"; bash "$UNINSTALL_PATH" --restore-only ;;
    --update)  choose_language; require_root; check_updates ;;
    --uninstall|--revert) choose_language; require_root; run_uninstaller ;;
    --menu)    choose_language; run_menu ;;
    "")
      choose_language
      if [[ "$(state_get INSTALLED)" == "1" ]]; then
        run_menu
      else
        install_all
        run_menu
      fi ;;
    *) usage >&2; exit 1 ;;
  esac
}

# Set SECURITY_DNS_SOURCE_ONLY=1 to load the functions without running (for tests).
if [[ "${SECURITY_DNS_SOURCE_ONLY:-0}" != "1" ]]; then
  main "$@"
fi
