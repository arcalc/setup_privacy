#Requires -Version 5.1
<#
.SYNOPSIS
    Security DNS - Windows CLI (installer and control menu).

.DESCRIPTION
    Tools (each one can be controlled independently):
      spoofdpi   local proxy that splits the TLS handshake to bypass DPI
      warp       Cloudflare WARP client (encrypted tunnel to Cloudflare)
      wireguard  the same WARP tunnel through WireGuard, profile made by wgcf

    Actions per tool: install, start, stop, enable (autostart), disable, uninstall.
    Kill switch: stops every tool at once and keeps encrypted DNS (DoH) on.
    Smart recovery: when a step fails, the script classifies the error, explains it,
    proposes an automatic fix, and retries after you approve.

    Developer : https://arcalc.github.io/arcalc/
    Security  : thearcalc@protonmail.com  (never report vulnerabilities publicly)
    License   : MIT

.PARAMETER Menu       Opens the numbered menu.
.PARAMETER Kill       Kill switch: stop every tool, keep encrypted DNS.
.PARAMETER Restore    Restore original settings, keep the app and tools.
.PARAMETER Update     Check for updates.
.PARAMETER Uninstall  Remove everything and restore your settings. Alias: -Revert.
.PARAMETER Version    Print the version.

.EXAMPLE
    irm https://raw.githubusercontent.com/arcalc/setup_privacy/main/cli/install.ps1 | iex
#>
[CmdletBinding()]
param(
    [switch]$Menu,
    [switch]$Kill,
    [switch]$Restore,
    [switch]$Update,
    [switch]$Version,

    [Alias('Revert')]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
$ScriptVersion  = '3.0.0'
$RepoRaw        = 'https://raw.githubusercontent.com/arcalc/setup_privacy/main/cli'
$PortfolioUrl   = 'https://arcalc.github.io/arcalc/'
$ContactEmail   = 'thearcalc@protonmail.com'
$SpoofDpiRepo   = 'xvzc/SpoofDPI'
$WgcfRepo       = 'ViRb3/wgcf'
$WireGuardRepo  = 'WireGuard/wireguard-windows'

$AppDir         = Join-Path $env:ProgramData 'SecurityDNS'
$AppScript      = Join-Path $AppDir 'security-dns.ps1'
$AppUninstall   = Join-Path $AppDir 'uninstall.ps1'
$BinDir         = Join-Path $AppDir 'bin'
$WgcfDir        = Join-Path $AppDir 'wgcf'
$WgConf         = Join-Path $AppDir 'security-dns.conf'
$BackupDir      = Join-Path $AppDir 'backup'
$BackupFile     = Join-Path $BackupDir 'pre-install.json'
$StateFile      = Join-Path $AppDir 'state.json'
$SettingsFile   = Join-Path $AppDir 'settings.json'
$SpoofExe       = Join-Path $BinDir 'spoofdpi.exe'
$WgcfExe        = Join-Path $BinDir 'wgcf.exe'
$WgTunnelName   = 'security-dns'
$WgExe          = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
$WarpCli        = Join-Path $env:ProgramFiles 'Cloudflare\Cloudflare WARP\warp-cli.exe'
$WarpMsiUrl     = 'https://downloads.cloudflareclient.com/v1/download/windows/ga'
$StartupScript  = Join-Path ([Environment]::GetFolderPath('Startup')) 'security-dns.vbs'
$StartMenuDir   = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
$DesktopDir     = [Environment]::GetFolderPath('CommonDesktopDirectory')
$ProxyKey       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$MinDohBuild    = 19041
$Script:Lang    = 'en'
$Script:SkipSystemDns = $false

$SettingKeys = @('SPOOF_PORT', 'DNS_SERVERS', 'DOH_TEMPLATE', 'WG_ENDPOINT', 'SPOOF_ARG_STYLE',
    'SPOOF_EXTRA_FLAGS', 'SPOOF_PATH', 'WGCF_PATH', 'NET_TIMEOUT', 'GITHUB_TOKEN')

$SettingDefault = @{
    SPOOF_PORT        = '8080'
    DNS_SERVERS       = '1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001'
    DOH_TEMPLATE      = 'https://cloudflare-dns.com/dns-query'
    WG_ENDPOINT       = ''
    SPOOF_ARG_STYLE   = 'auto'
    SPOOF_EXTRA_FLAGS = ''
    SPOOF_PATH        = ''
    WGCF_PATH         = ''
    NET_TIMEOUT       = '30'
    GITHUB_TOKEN      = ''
}

# -----------------------------------------------------------------------------
# User-facing text. Only strings are translated; code stays in English.
# -----------------------------------------------------------------------------
$Messages = @{
    en = @{
        lang_title = 'Select your language:'
        lang_prompt = 'Enter 1 or 2'
        lang_bad = 'Please enter 1 or 2.'
        need_admin = 'Run this from an elevated PowerShell (Run as administrator).'
        press_enter = 'Press Enter to continue.'
        choose = 'Choose'
        bad_choice = 'Unknown option. Choose from the list.'
        menu_head = 'Security DNS v{0}'
        menu_quick = 'Quick modes (start one tool and stop the others):'
        menu_1 = '1) SpoofDPI          keeps your public IP; bypasses DPI on this computer'
        menu_2 = '2) Cloudflare WARP   hides destination IPs from your ISP; changes your public IP'
        menu_3 = '3) WireGuard (wgcf)  the same WARP tunnel through WireGuard; changes your public IP'
        menu_manage = 'Manage:'
        menu_4 = '4) Advanced Tool Manager  install, start, stop, enable, disable or remove each tool'
        menu_5 = '5) Settings               ports, DNS servers, WireGuard endpoint, tool paths'
        menu_6 = '6) Status'
        menu_7 = '7) Check for updates'
        menu_8 = '8) Restore original settings  undo DNS and proxy changes; keeps the app and tools'
        menu_9 = '9) KILL SWITCH  turn off every tool now; encrypted DNS stays on'
        menu_a = 'a) About, contact and security policy'
        menu_u = 'u) Uninstall everything'
        menu_q = 'q) Quit'
        tunnel_warn = 'WARNING: this tool hides destination IPs from your ISP, but your public IP changes, your apparent country may change (traffic exits at the nearest Cloudflare data center), and traffic volume stays visible to your ISP.'
        continue_q = 'Continue?'
        unchanged = 'Nothing was changed.'
        done_ok = 'Done.'
        tm_head = 'Advanced Tool Manager'
        tm_hint = 'Pick a tool to control it on its own. Tools do not depend on each other.'
        tm_all = 'i) Install all missing tools'
        tm_kill = 'k) KILL SWITCH: turn off every tool now'
        tm_back = 'b) Back'
        tool_spoofdpi = 'SpoofDPI - a local proxy that splits your TLS handshake so DPI equipment cannot read website names. Keeps your public IP.'
        tool_warp = 'Cloudflare WARP - an encrypted tunnel to Cloudflare that hides destination IPs from your ISP. Changes your public IP and may change your apparent country.'
        tool_wireguard = 'WireGuard (wgcf) - the same Cloudflare WARP tunnel run by the standard WireGuard client with a profile made by wgcf. Same trade-offs as WARP.'
        act_install = '1) Install    - download and install the tool; nothing starts yet'
        act_start = '2) Start      - run it now (stops again on Stop or sign-out unless enabled)'
        act_stop = '3) Stop       - stop it now; nothing is deleted'
        act_enable = '4) Enable     - start it automatically at sign-in or boot'
        act_disable = '5) Disable    - do not start it automatically'
        act_uninstall = '6) Uninstall  - stop it and delete what this app installed for it'
        st_installed = 'installed'
        st_missing = 'not installed'
        st_running = 'running'
        st_stopped = 'stopped'
        st_enabled = 'autostart on'
        st_disabled = 'autostart off'
        stat_dns = 'Encrypted DNS'
        kill_start = 'Turning off all tools...'
        kill_done = 'All tools are off. Encrypted DNS is on.'
        kill_partial = 'Some tools could not be stopped. Check the messages above.'
        restore_q = 'Restore your original network, DNS and proxy settings and stop all tools? The app and tools stay installed.'
        restore_done = 'Original settings restored. The app and tools are still installed.'
        restore_fail = 'Restore did not complete. Check the messages above.'
        uninst_q = 'Uninstall Security DNS completely and restore your original settings?'
        set_head = 'Settings'
        set_hint = 'Type a number to change a setting. r = reset all to defaults, b = back.'
        set_SPOOF_PORT = 'SpoofDPI port - where SpoofDPI listens on this computer (default 8080). If busy, a free port is chosen for you.'
        set_DNS_SERVERS = 'DNS servers - encrypted DNS server addresses used for every lookup, space separated (default: Cloudflare IPv4 and IPv6).'
        set_DOH_TEMPLATE = 'DoH template - the DNS-over-HTTPS address your DNS servers use (default: the Cloudflare address). Must match your DNS servers.'
        set_WG_ENDPOINT = 'WireGuard endpoint - replaces the server address (host:port) in the WireGuard profile. Empty keeps the Cloudflare default.'
        set_SPOOF_ARG_STYLE = 'SpoofDPI argument style - auto, config, flags, port or none. Auto reads the installed build help.'
        set_SPOOF_EXTRA_FLAGS = 'SpoofDPI extra flags - added to the SpoofDPI command line. Advanced.'
        set_SPOOF_PATH = 'SpoofDPI program path - use your own program instead of the downloaded one. Empty = managed copy.'
        set_WGCF_PATH = 'wgcf program path - use your own wgcf program. Empty = managed copy.'
        set_NET_TIMEOUT = 'Network timeout - seconds to wait for connections (5-300, default 30).'
        set_GITHUB_TOKEN = 'GitHub token - optional, avoids GitHub download rate limits. Stored only on this computer.'
        set_current = 'current'
        set_prompt = 'New value (empty keeps it, a single - clears it)'
        set_saved = 'Saved.'
        set_invalid = 'That value is not valid for this setting.'
        set_reset_q = 'Reset all settings to their defaults?'
        pd_what = 'What went wrong:'
        pd_prop = 'Proposed solution:'
        pd_details = 'Technical details:'
        pd_choose = '[a] Apply fix   [x] Cancel'
        fix_applied = 'Fix applied. Resuming the operation...'
        fix_failed = 'The fix could not be applied.'
        giving_up = 'The same problem keeps happening, so the operation was stopped.'
        cancelled = 'Cancelled.'
        p_port_in_use_t = 'Port is already taken'
        p_port_in_use_e = 'Another application is using the port SpoofDPI needs.'
        p_port_in_use_f = 'I will choose a free port automatically and save it in Settings.'
        p_unsupported_flag_t = 'SpoofDPI does not accept these options'
        p_unsupported_flag_e = 'The installed SpoofDPI version rejected the startup options.'
        p_unsupported_flag_f = 'I will switch to a different option style (config file, flags, port only, or none) and retry.'
        p_network_t = 'Network problem'
        p_network_e = 'A connection timed out or the server could not be reached.'
        p_network_f = 'I will wait a moment, raise the network timeout, and retry.'
        p_ratelimit_t = 'Download limit reached'
        p_ratelimit_e = 'GitHub is limiting requests from your network.'
        p_ratelimit_f = 'I will wait 30 seconds and retry. A GitHub token in Settings avoids this.'
        p_permission_t = 'Permission denied'
        p_permission_e = 'Windows refused the operation because of missing permissions.'
        p_permission_f = 'I will retry once. If it fails again, run PowerShell as administrator.'
        p_conflict_t = 'Two tunnels cannot run together'
        p_conflict_e = 'Cloudflare WARP and WireGuard both route all traffic, so they conflict.'
        p_conflict_f = 'I will stop the other tunnel and then start this one.'
        p_no_asset_t = 'No download found for this system'
        p_no_asset_e = 'The project does not publish a build for this operating system or CPU.'
        p_no_asset_f = 'I will open Settings so you can point to a program you built yourself.'
        p_doh_unsupported_t = 'This Windows version cannot use system DNS-over-HTTPS'
        p_doh_unsupported_e = 'System-wide DNS-over-HTTPS needs Windows 10 version 2004 (build 19041) or newer.'
        p_doh_unsupported_f = 'I will continue without changing system DNS (no plaintext is sent to the DNS servers). Enable Secure DNS in your browser instead.'
        p_unknown_t = 'Unexpected error'
        p_unknown_e = 'The operation failed for a reason I do not recognize.'
        p_unknown_f = 'I will retry the operation. The technical details below show the cause.'
        doh_skipped = 'System DNS-over-HTTPS was skipped. Enable Secure DNS in your browser.'
        port_busy = 'Port {0} is taken by another application. Choosing another port.'
        port_switched = 'SpoofDPI will use port {0}.'
        start_ok = 'SpoofDPI is listening on 127.0.0.1:{0}.'
        start_fail = 'SpoofDPI did not start and listen on its port. Its log output follows.'
        first_run = 'Installing Security DNS for the first time.'
        first_start_q = 'Download and start SpoofDPI now?'
        done_title = 'Security DNS is installed.'
        done_menu = 'Open the menu any time from the Security DNS shortcut.'
        done_next = 'Restart your browsers, then enable ECH and disable QUIC (see README.md).'
        about_head = 'About Security DNS'
        about_dev = 'Developer portfolio : {0}'
        about_mail = 'Support and security email : {0}'
        about_sec_title = 'Security policy'
        about_sec_text = 'Do NOT open public issues for security vulnerabilities. Report them privately by email to {0}, or through the GitHub Private Vulnerability Reporting (repository Security tab, Report a vulnerability). This protects the community until a fix is released.'
        about_license = 'License: MIT'
    }
    ar = @{
        lang_title = 'اختر لغتك:'
        lang_prompt = 'أدخل 1 أو 2'
        lang_bad = 'يرجى إدخال 1 أو 2.'
        need_admin = 'شغّل هذا الأمر من PowerShell بصلاحيات المسؤول (Run as administrator).'
        press_enter = 'اضغط Enter للمتابعة.'
        choose = 'اختر'
        bad_choice = 'خيار غير معروف. اختر من القائمة.'
        menu_head = 'Security DNS الإصدار {0}'
        menu_quick = 'أوضاع سريعة (تشغّل أداة واحدة وتوقف البقية):'
        menu_1 = '1) SpoofDPI          يحافظ على عنوان IP العام؛ يتجاوز فحص الحزم على هذا الجهاز'
        menu_2 = '2) Cloudflare WARP   يخفي عناوين الوجهات عن مزود الإنترنت؛ يغيّر عنوان IP العام'
        menu_3 = '3) WireGuard (wgcf)  نفس نفق WARP عبر WireGuard؛ يغيّر عنوان IP العام'
        menu_manage = 'الإدارة:'
        menu_4 = '4) مدير الأدوات المتقدم  تثبيت، تشغيل، إيقاف، تفعيل، تعطيل أو حذف كل أداة'
        menu_5 = '5) الإعدادات             المنافذ، خوادم DNS، نقطة اتصال WireGuard، مسارات الأدوات'
        menu_6 = '6) الحالة'
        menu_7 = '7) التحقق من التحديثات'
        menu_8 = '8) استعادة الإعدادات الأصلية  تراجع عن تغييرات DNS والوكيل؛ يبقي التطبيق والأدوات'
        menu_9 = '9) مفتاح الإيقاف الطارئ  أوقف كل الأدوات الآن؛ يبقى DNS المشفّر مفعّلاً'
        menu_a = 'a) حول التطبيق والتواصل وسياسة الأمان'
        menu_u = 'u) إلغاء التثبيت بالكامل'
        menu_q = 'q) خروج'
        tunnel_warn = 'تحذير: تخفي هذه الأداة عناوين الوجهات عن مزود الإنترنت، لكن عنوان IP العام سيتغير، وقد يتغير البلد الظاهر لك (يخرج الاتصال من أقرب مركز بيانات لـ Cloudflare)، ويبقى حجم الحركة مرئياً لمزود الإنترنت.'
        continue_q = 'هل تريد المتابعة؟'
        unchanged = 'لم يتم تغيير أي شيء.'
        done_ok = 'تم.'
        tm_head = 'مدير الأدوات المتقدم'
        tm_hint = 'اختر أداة للتحكم بها بشكل مستقل. الأدوات لا تعتمد على بعضها.'
        tm_all = 'i) تثبيت كل الأدوات الناقصة'
        tm_kill = 'k) مفتاح الإيقاف الطارئ: أوقف كل الأدوات الآن'
        tm_back = 'b) رجوع'
        tool_spoofdpi = 'SpoofDPI - وكيل محلي يقسّم مصافحة TLS حتى لا تتمكن أجهزة الفحص من قراءة أسماء المواقع. يحافظ على عنوان IP العام.'
        tool_warp = 'Cloudflare WARP - نفق مشفّر إلى Cloudflare يخفي عناوين الوجهات عن مزود الإنترنت. يغيّر عنوان IP العام وقد يغيّر البلد الظاهر لك.'
        tool_wireguard = 'WireGuard (wgcf) - نفس نفق Cloudflare WARP لكن عبر عميل WireGuard القياسي بملف أنشأه wgcf. نفس سلبيات WARP.'
        act_install = '1) تثبيت   - تنزيل الأداة وتثبيتها؛ لا يبدأ شيء بعد'
        act_start = '2) تشغيل   - شغّلها الآن (تتوقف عند الإيقاف أو تسجيل الخروج ما لم تُفعَّل)'
        act_stop = '3) إيقاف   - أوقفها الآن؛ لا يُحذف شيء'
        act_enable = '4) تفعيل   - تبدأ تلقائياً عند تسجيل الدخول أو الإقلاع'
        act_disable = '5) تعطيل   - لا تبدأ تلقائياً'
        act_uninstall = '6) حذف     - أوقفها واحذف ما ثبّته التطبيق لها'
        st_installed = 'مثبّتة'
        st_missing = 'غير مثبّتة'
        st_running = 'تعمل'
        st_stopped = 'متوقفة'
        st_enabled = 'البدء التلقائي مفعّل'
        st_disabled = 'البدء التلقائي معطّل'
        stat_dns = 'DNS المشفّر'
        kill_start = 'جارٍ إيقاف كل الأدوات...'
        kill_done = 'كل الأدوات متوقفة. DNS المشفّر مفعّل.'
        kill_partial = 'تعذّر إيقاف بعض الأدوات. راجع الرسائل أعلاه.'
        restore_q = 'هل تريد استعادة إعدادات الشبكة والـDNS والوكيل الأصلية وإيقاف كل الأدوات؟ يبقى التطبيق والأدوات مثبّتة.'
        restore_done = 'تمت استعادة الإعدادات الأصلية. ما زال التطبيق والأدوات مثبّتة.'
        restore_fail = 'لم تكتمل عملية الاستعادة. راجع الرسائل أعلاه.'
        uninst_q = 'هل تريد إلغاء تثبيت Security DNS بالكامل واستعادة إعداداتك الأصلية؟'
        set_head = 'الإعدادات'
        set_hint = 'اكتب رقماً لتغيير إعداد. r = إعادة كل الإعدادات للافتراضي، b = رجوع.'
        set_SPOOF_PORT = 'منفذ SpoofDPI - المنفذ الذي يستمع عليه SpoofDPI على هذا الجهاز (الافتراضي 8080). إن كان مشغولاً يُختار منفذ حر تلقائياً.'
        set_DNS_SERVERS = 'خوادم DNS - عناوين خوادم DNS المشفّرة لكل الاستعلامات، مفصولة بمسافة (الافتراضي: Cloudflare IPv4 وIPv6).'
        set_DOH_TEMPLATE = 'قالب DoH - عنوان DNS عبر HTTPS الذي تستخدمه خوادمك (الافتراضي: عنوان Cloudflare). يجب أن يطابق خوادم DNS.'
        set_WG_ENDPOINT = 'نقطة اتصال WireGuard - تستبدل عنوان الخادم (host:port) في ملف WireGuard. الفارغ يبقي افتراضي Cloudflare.'
        set_SPOOF_ARG_STYLE = 'نمط خيارات SpoofDPI - auto أو config أو flags أو port أو none. وضع auto يقرأ --help للإصدار المثبّت.'
        set_SPOOF_EXTRA_FLAGS = 'خيارات إضافية لـ SpoofDPI - تُضاف إلى سطر أوامر SpoofDPI. للمتقدمين.'
        set_SPOOF_PATH = 'مسار برنامج SpoofDPI - استخدم برنامجك بدل المنزّل. الفارغ = النسخة المُدارة.'
        set_WGCF_PATH = 'مسار برنامج wgcf - استخدم برنامج wgcf الخاص بك. الفارغ = النسخة المُدارة.'
        set_NET_TIMEOUT = 'مهلة الشبكة - ثوانٍ لانتظار الاتصالات (5-300، الافتراضي 30).'
        set_GITHUB_TOKEN = 'رمز GitHub - اختياري، يتجنب حدود التنزيل من GitHub. يُحفظ على هذا الجهاز فقط.'
        set_current = 'الحالي'
        set_prompt = 'القيمة الجديدة (الفارغ يبقيها، وعلامة - وحدها تمسحها)'
        set_saved = 'تم الحفظ.'
        set_invalid = 'هذه القيمة غير صالحة لهذا الإعداد.'
        set_reset_q = 'هل تريد إعادة كل الإعدادات إلى قيمها الافتراضية؟'
        pd_what = 'ما الذي حدث:'
        pd_prop = 'الحل المقترح:'
        pd_details = 'التفاصيل التقنية:'
        pd_choose = '[a] تطبيق الحل   [x] إلغاء'
        fix_applied = 'تم تطبيق الحل. جارٍ استئناف العملية...'
        fix_failed = 'تعذّر تطبيق الحل.'
        giving_up = 'تتكرر المشكلة نفسها، لذلك أُوقفت العملية.'
        cancelled = 'تم الإلغاء.'
        p_port_in_use_t = 'المنفذ مشغول'
        p_port_in_use_e = 'تطبيق آخر يستخدم المنفذ الذي يحتاجه SpoofDPI.'
        p_port_in_use_f = 'سأختار منفذاً حراً تلقائياً وأحفظه في الإعدادات.'
        p_unsupported_flag_t = 'SpoofDPI لا يقبل هذه الخيارات'
        p_unsupported_flag_e = 'رفض إصدار SpoofDPI المثبّت خيارات التشغيل.'
        p_unsupported_flag_f = 'سأنتقل إلى نمط خيارات مختلف (ملف إعداد أو خيارات أو منفذ فقط أو بدون) وأعيد المحاولة.'
        p_network_t = 'مشكلة في الشبكة'
        p_network_e = 'انتهت مهلة اتصال أو تعذّر الوصول إلى الخادم.'
        p_network_f = 'سأنتظر قليلاً وأرفع مهلة الشبكة وأعيد المحاولة.'
        p_ratelimit_t = 'تم بلوغ حد التنزيل'
        p_ratelimit_e = 'تقيّد GitHub الطلبات القادمة من شبكتك.'
        p_ratelimit_f = 'سأنتظر 30 ثانية وأعيد المحاولة. رمز GitHub في الإعدادات يتجنب هذا.'
        p_permission_t = 'تم رفض الإذن'
        p_permission_e = 'رفض Windows العملية بسبب نقص الصلاحيات.'
        p_permission_f = 'سأعيد المحاولة مرة واحدة. إن فشلت فشغّل PowerShell بصلاحيات المسؤول.'
        p_conflict_t = 'لا يمكن تشغيل نفقين معاً'
        p_conflict_e = 'يوجّه Cloudflare WARP وWireGuard كل الحركة، لذلك يتعارضان.'
        p_conflict_f = 'سأوقف النفق الآخر ثم أشغّل هذا.'
        p_no_asset_t = 'لا يوجد ملف تنزيل لهذا النظام'
        p_no_asset_e = 'لا ينشر المشروع إصداراً لهذا النظام أو هذا المعالج.'
        p_no_asset_f = 'سأفتح الإعدادات لتحدد برنامجاً بنيته بنفسك.'
        p_doh_unsupported_t = 'هذا الإصدار من Windows لا يدعم DNS عبر HTTPS على مستوى النظام'
        p_doh_unsupported_e = 'يحتاج DNS عبر HTTPS على مستوى النظام إلى Windows 10 الإصدار 2004 (البناء 19041) أو أحدث.'
        p_doh_unsupported_f = 'سأتابع دون تغيير DNS النظام (لا يُرسل نص غير مشفّر إلى خوادم DNS). فعّل DNS الآمن في متصفحك بدلاً من ذلك.'
        p_unknown_t = 'خطأ غير متوقع'
        p_unknown_e = 'فشلت العملية لسبب لا أتعرف عليه.'
        p_unknown_f = 'سأعيد المحاولة. توضح التفاصيل التقنية أدناه السبب.'
        doh_skipped = 'تم تخطي DNS عبر HTTPS على مستوى النظام. فعّل DNS الآمن في متصفحك.'
        port_busy = 'المنفذ {0} مشغول بتطبيق آخر. سيتم اختيار منفذ آخر.'
        port_switched = 'سيستخدم SpoofDPI المنفذ {0}.'
        start_ok = 'SpoofDPI يستمع الآن على 127.0.0.1:{0}.'
        start_fail = 'لم يبدأ SpoofDPI ولم يستمع على منفذه. مخرجات سجله التالية.'
        first_run = 'جارٍ تثبيت Security DNS لأول مرة.'
        first_start_q = 'هل تريد تنزيل SpoofDPI وتشغيله الآن؟'
        done_title = 'تم تثبيت Security DNS.'
        done_menu = 'افتح القائمة في أي وقت من اختصار Security DNS.'
        done_next = 'أعد تشغيل المتصفح، ثم فعّل ECH وعطّل QUIC (راجع README.md).'
        about_head = 'حول Security DNS'
        about_dev = 'موقع المطوّر : {0}'
        about_mail = 'البريد للدعم والأمان : {0}'
        about_sec_title = 'سياسة الأمان'
        about_sec_text = 'لا تفتح مشكلات عامة (public issues) للثغرات الأمنية. أبلغ عنها بشكل خاص عبر البريد {0} أو عبر ميزة الإبلاغ الخاص عن الثغرات في GitHub (تبويب Security في المستودع ثم Report a vulnerability). هذا يحمي المجتمع حتى يصدر الإصلاح.'
        about_license = 'الرخصة: MIT'
    }
}

# -----------------------------------------------------------------------------
# Reused helpers (backup, proxy, DoH check, downloads, shortcuts)
# -----------------------------------------------------------------------------
function T([string]$Key) {
    $table = $Messages[$Script:Lang]
    if ($table.ContainsKey($Key)) { return [string]$table[$Key] }
    return $Key
}

function Choose-Language {
    while ($true) {
        Write-Host ''
        Write-Host "  $($Messages.en.lang_title)  /  $($Messages.ar.lang_title)"
        Write-Host ''
        Write-Host '  1) English'
        Write-Host '  2) العربية'
        Write-Host ''
        $answer = (Read-Host "$($Messages.en.lang_prompt) / $($Messages.ar.lang_prompt)").Trim()
        if ($answer -eq '1') { $Script:Lang = 'en'; return }
        if ($answer -eq '2') { $Script:Lang = 'ar'; return }
        Write-Host "  $($Messages.en.lang_bad) / $($Messages.ar.lang_bad)"
    }
}

function Write-Step([string]$Text)    { Write-Host "`n==> $Text" -ForegroundColor Cyan }

function Write-Good([string]$Text)    { Write-Host "[+] $Text" -ForegroundColor Green }

function Write-Caution([string]$Text) { Write-Host "[!] $Text" -ForegroundColor Yellow }

function Confirm-Action([string]$Question) {
    $reply = Read-Host "$Question [y/N]"
    return ($reply -match '^[Yy]([Ee][Ss])?$')
}

function Test-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-State {
    if (Test-Path -LiteralPath $StateFile) {
        return (Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json)
    }
    return [pscustomobject]@{}
}

function Get-StateValue([string]$Key) {
    $state = Read-State
    $prop = $state.PSObject.Properties[$Key]
    if ($prop) { return $prop.Value }
    return $null
}

function Set-StateValue([string]$Key, $Value) {
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
    $state = Read-State
    $table = [ordered]@{}
    foreach ($prop in $state.PSObject.Properties) { $table[$prop.Name] = $prop.Value }
    $table[$Key] = $Value
    $table | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StateFile -Encoding UTF8
}

function Get-RegistryValue([string]$Path, [string]$Name) {
    $item   = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $exists = ($null -ne $item) -and ($item.PSObject.Properties.Name -contains $Name)
    $value  = $null
    if ($exists) { $value = $item.$Name }
    return [pscustomobject]@{ Exists = $exists; Value = $value }
}

function Update-WinInet {
    if (-not ('SecurityDns.WinInet' -as [type])) {
        Add-Type -Namespace SecurityDns -Name WinInet -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
    }
    # 39 = INTERNET_OPTION_SETTINGS_CHANGED, 37 = INTERNET_OPTION_REFRESH
    [void][SecurityDns.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][SecurityDns.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
}

function Test-PortInUse([int]$Port) {
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

function Get-ProductCodeByName([string]$Pattern) {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($item in @(Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue)) {
        if ($item.DisplayName -like $Pattern) { return $item.PSChildName }
    }
    return $null
}

function Invoke-MsiexecInstall([string]$MsiPath) {
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', "`"$MsiPath`"", '/qn', '/norestart') -Wait -PassThru
    if ($proc.ExitCode -notin 0, 3010) { throw "The installer exited with code $($proc.ExitCode)." }
}

function Test-DohSupported {
    $build  = [int](Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
    $hasCmd = [bool](Get-Command -Name Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
    return [pscustomobject]@{ Build = $build; Supported = (($build -ge $MinDohBuild) -and $hasCmd) }
}

function Save-PreInstallState {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    if (Test-Path -LiteralPath $BackupFile) {
        Write-Good 'Original backup already exists; keeping it.'
        return
    }

    $proxy = [ordered]@{
        ProxyEnable   = Get-RegistryValue $ProxyKey 'ProxyEnable'
        ProxyServer   = Get-RegistryValue $ProxyKey 'ProxyServer'
        ProxyOverride = Get-RegistryValue $ProxyKey 'ProxyOverride'
        AutoConfigURL = Get-RegistryValue $ProxyKey 'AutoConfigURL'
    }

    $dns = foreach ($adapter in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        $cfg = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
            -Filter "InterfaceIndex = $($adapter.ifIndex)" -ErrorAction SilentlyContinue
        if ($cfg) {
            [pscustomobject]@{
                InterfaceIndex = [int]$adapter.ifIndex
                Alias          = $adapter.Name
                Dhcp           = [bool]$cfg.DHCPEnabled
                Servers        = @($cfg.DNSServerSearchOrder | Where-Object { $_ })
            }
        }
    }

    $doh = @()
    if (Get-Command -Name Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
        $doh = @(Get-DnsClientDohServerAddress | ForEach-Object {
            [pscustomobject]@{
                ServerAddress      = $_.ServerAddress
                DohTemplate        = $_.DohTemplate
                AllowFallbackToUdp = [bool]$_.AllowFallbackToUdp
                AutoUpgrade        = [bool]$_.AutoUpgrade
            }
        })
    }

    $startupExisted = Test-Path -LiteralPath $StartupScript
    if ($startupExisted) {
        Copy-Item -LiteralPath $StartupScript -Destination (Join-Path $BackupDir 'security-dns.vbs.orig') -Force
    }

    $state = [ordered]@{
        Version = 1
        Created = (Get-Date).ToString('o')
        Proxy   = $proxy
        Dns     = @($dns | Where-Object { $_ })
        Doh     = $doh
        Startup = [pscustomobject]@{ Existed = $startupExisted }
    }
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $BackupFile -Encoding UTF8
    Write-Good "Original settings backed up to $BackupFile"
}

function Get-SpoofDpiRelease {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$SpoofDpiRepo/releases/latest" -Headers (Get-GitHubHeaders)
    $assets  = @($release.assets)

    $bin = $assets |
        Where-Object { $_.name -match 'windows' -and $_.name -match 'amd64' -and $_.name -match '\.(zip|exe)$' } |
        Sort-Object { $_.name -notmatch '\.zip$' } |
        Select-Object -First 1
    if (-not $bin) { throw "No windows-amd64 asset found in SpoofDPI release $($release.tag_name)." }

    $sums = $assets |
        Where-Object { $_.name -match 'sha256|checksum' -and $_.name -notmatch 'linux|darwin|macos|arm' } |
        Select-Object -First 1

    $sumsUrl = $null
    if ($sums) { $sumsUrl = $sums.browser_download_url }

    return [pscustomobject]@{
        Tag     = $release.tag_name
        Name    = $bin.name
        Url     = $bin.browser_download_url
        SumsUrl = $sumsUrl
    }
}

function Test-FileSha256([string]$File, [string]$SumsFile, [string]$Name) {
    $lines = @(Get-Content -LiteralPath $SumsFile | Where-Object { $_.Trim() })
    $line  = $lines | Where-Object { $_ -match [regex]::Escape($Name) } | Select-Object -First 1
    if (-not $line -and $lines.Count -gt 0) { $line = $lines[0] }

    $expected = ([string]$line -split '\s+')[0]
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') {
        Write-Caution 'Checksum file could not be parsed; skipping verification.'
        return
    }

    $actual = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash
    if ($actual -ne $expected.ToUpperInvariant()) { throw "SHA-256 mismatch for $Name. Refusing to install." }
    Write-Good 'SHA-256 checksum verified.'
}

function Install-SpoofDpiBinary {
    $release = Get-SpoofDpiRelease
    if ((Get-StateValue 'SPOOFDPI_TAG') -eq $release.Tag -and (Test-Path -LiteralPath $SpoofExe)) {
        Write-Good "SpoofDPI is up to date ($($release.Tag))."
        return
    }

    $tmp = Join-Path $env:TEMP ('sdns-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $file = Join-Path $tmp $release.Name
        Invoke-WebRequest -Uri $release.Url -OutFile $file -UseBasicParsing

        if ($release.SumsUrl) {
            $sumsFile = Join-Path $tmp 'checksums.txt'
            Invoke-WebRequest -Uri $release.SumsUrl -OutFile $sumsFile -UseBasicParsing
            Test-FileSha256 -File $file -SumsFile $sumsFile -Name $release.Name
        } else {
            Write-Caution 'No checksum published for this release; integrity was not verified.'
        }

        if ($file -like '*.zip') {
            $extract = Join-Path $tmp 'extract'
            Expand-Archive -LiteralPath $file -DestinationPath $extract -Force
            $exe = Get-ChildItem -LiteralPath $extract -Recurse -Filter 'spoofdpi*.exe' | Select-Object -First 1
            if (-not $exe) { throw 'spoofdpi.exe was not found inside the downloaded archive.' }
            $source = $exe.FullName
        } else {
            $source = $file
        }

        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $SpoofExe -Force
        Set-StateValue 'SPOOFDPI_TAG' $release.Tag
        Write-Good "Installed SpoofDPI $($release.Tag)"
    }
    finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Remove-StartupLauncher {
    Remove-Item -LiteralPath $StartupScript -Force -ErrorAction SilentlyContinue
}

function Set-SystemProxy([int]$Port) {
    if ((Get-RegistryValue $ProxyKey 'AutoConfigURL').Exists) {
        Write-Caution 'An automatic configuration (PAC) URL was set. It is disabled while mode 1 runs; the original value is backed up.'
    }
    Remove-ItemProperty -Path $ProxyKey -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $ProxyKey -Name 'ProxyServer'   -Value "127.0.0.1:$Port" -Type String
    Set-ItemProperty -Path $ProxyKey -Name 'ProxyOverride' -Value 'localhost;127.*;10.*;192.168.*;<local>' -Type String
    Set-ItemProperty -Path $ProxyKey -Name 'ProxyEnable'   -Value 1 -Type DWord
    Update-WinInet
    Write-Good "System proxy set to 127.0.0.1:$Port"
}

function Disable-SystemProxy {
    Set-ItemProperty -Path $ProxyKey -Name 'ProxyEnable' -Value 0 -Type DWord
    Update-WinInet
}

function Install-WarpClient {
    if (Test-Path -LiteralPath $WarpCli) {
        Write-Good 'Cloudflare WARP client is already installed; it will be left in place on uninstall.'
    } else {
        $msi = Join-Path $env:TEMP ('warp-' + [guid]::NewGuid().ToString('N') + '.msi')
        try {
            Invoke-WebRequest -Uri $WarpMsiUrl -OutFile $msi -UseBasicParsing
            Set-StateValue 'WARP_MSI_ADDED' $true
            Invoke-MsiexecInstall -MsiPath $msi
        }
        finally {
            Remove-Item -LiteralPath $msi -Force -ErrorAction SilentlyContinue
        }
        Set-StateValue 'WARP_PRODUCT_CODE' (Get-ProductCodeByName 'Cloudflare WARP*')
        Write-Good 'Cloudflare WARP client installed.'
    }

    if (-not (Test-Path -LiteralPath $WarpCli)) { throw 'warp-cli.exe was not found after installation.' }

    Start-Sleep -Seconds 3
    & $WarpCli --accept-tos registration show *> $null
    if ($LASTEXITCODE -ne 0) {
        & $WarpCli --accept-tos registration new *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Could not register the WARP client.' }
        Set-StateValue 'WARP_REGISTERED_BY_US' $true
    }
}

function Disconnect-Warp {
    if (Test-Path -LiteralPath $WarpCli) {
        & $WarpCli --accept-tos disconnect *> $null
    }
}

function Install-WireGuardClient {
    if (Test-Path -LiteralPath $WgExe) { return }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$WireGuardRepo/releases/latest" -Headers (Get-GitHubHeaders)
    $asset = @($release.assets) | Where-Object { $_.name -match '^wireguard-amd64-.*\.msi$' } | Select-Object -First 1
    if (-not $asset) { throw 'No WireGuard MSI asset was found in the latest release.' }

    $msi = Join-Path $env:TEMP $asset.name
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $msi -UseBasicParsing
        Set-StateValue 'WG_CLIENT_ADDED' $true
        Invoke-MsiexecInstall -MsiPath $msi
    }
    finally {
        Remove-Item -LiteralPath $msi -Force -ErrorAction SilentlyContinue
    }
    Set-StateValue 'WG_PRODUCT_CODE' (Get-ProductCodeByName 'WireGuard*')
    Write-Good 'WireGuard client installed.'
}

function Install-Wgcf {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$WgcfRepo/releases/latest" -Headers (Get-GitHubHeaders)
    $tag = [string]$release.tag_name

    if ((Test-Path -LiteralPath $WgcfExe) -and ((Get-StateValue 'WGCF_TAG') -eq $tag)) {
        Write-Good "wgcf is up to date ($tag)."
        return
    }

    $asset = @($release.assets) | Where-Object { $_.name -match 'windows_amd64\.exe$' } | Select-Object -First 1
    if (-not $asset) { throw "No windows_amd64 wgcf asset found in release $tag." }

    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    if (-not (Test-Path -LiteralPath $WgcfExe)) { Set-StateValue 'WGCF_EXE_ADDED' $true }
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $WgcfExe -UseBasicParsing
    Set-StateValue 'WGCF_TAG' $tag
    Write-Good "Installed wgcf $tag"
}

function New-AppShortcut([string]$Path) {
    $shell = New-Object -ComObject WScript.Shell
    $link  = $shell.CreateShortcut($Path)
    $link.TargetPath       = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $link.Arguments        = "-NoProfile -ExecutionPolicy Bypass -File `"$AppScript`" -Menu"
    $link.WorkingDirectory = $AppDir
    $link.Description      = 'Security DNS menu'
    $link.Save()

    # Set the "Run as administrator" flag: bit 0x20 of byte 0x15 in the .lnk header.
    $bytes = [IO.File]::ReadAllBytes($Path)
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Install-Shortcuts {
    $created = @()
    foreach ($dir in @($StartMenuDir, $DesktopDir)) {
        if (-not $dir) { continue }
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $path = Join-Path $dir 'Security DNS.lnk'
        New-AppShortcut -Path $path
        $created += $path
    }
    Set-StateValue 'SHORTCUTS' $created
    Write-Good 'Start Menu and Desktop shortcuts created.'
}

function Install-AppFiles {
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null

    $self = $PSCommandPath
    if ($self -and (Test-Path -LiteralPath $self)) {
        if ([IO.Path]::GetFullPath($self) -ne [IO.Path]::GetFullPath($AppScript)) {
            Copy-Item -LiteralPath $self -Destination $AppScript -Force
        }
        $sibling = Join-Path (Split-Path -Parent $self) 'uninstall.ps1'
        if (Test-Path -LiteralPath $sibling) {
            Copy-Item -LiteralPath $sibling -Destination $AppUninstall -Force
        } else {
            Invoke-WebRequest -Uri "$RepoRaw/uninstall.ps1" -OutFile $AppUninstall -UseBasicParsing
        }
    } else {
        Invoke-WebRequest -Uri "$RepoRaw/install.ps1" -OutFile $AppScript -UseBasicParsing
        Invoke-WebRequest -Uri "$RepoRaw/uninstall.ps1" -OutFile $AppUninstall -UseBasicParsing
    }
    Write-Good "Application files installed to $AppDir"
}

# -----------------------------------------------------------------------------
# Settings (settings.json, edited from the Settings menu)
# -----------------------------------------------------------------------------
function Read-Settings {
    $table = @{}
    if (Test-Path -LiteralPath $SettingsFile) {
        $raw = Get-Content -LiteralPath $SettingsFile -Raw
        if ($raw -and $raw.Trim()) {
            $obj = $raw | ConvertFrom-Json
            foreach ($prop in $obj.PSObject.Properties) { $table[$prop.Name] = [string]$prop.Value }
        }
    }
    return $table
}

function Get-Setting([string]$Key) {
    $settings = Read-Settings
    if ($settings.ContainsKey($Key)) { return [string]$settings[$Key] }
    return [string]$SettingDefault[$Key]
}

function Set-Setting([string]$Key, [string]$Value) {
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
    $settings = Read-Settings
    $settings[$Key] = $Value
    ($settings | ConvertTo-Json) | Set-Content -LiteralPath $SettingsFile -Encoding UTF8
}

function Test-SettingValid([string]$Key, [string]$Value) {
    switch ($Key) {
        'SPOOF_PORT'   { return ($Value -match '^\d+$') -and ([int]$Value -ge 1) -and ([int]$Value -le 65535) }
        'DNS_SERVERS'  {
            if (-not $Value.Trim()) { return $false }
            foreach ($item in ($Value.Trim() -split '\s+')) { if ($item -notmatch '^[0-9A-Fa-f:.]+$') { return $false } }
            return $true
        }
        'DOH_TEMPLATE' { return ($Value -match '^https://\S+$') }
        'WG_ENDPOINT'  { return ($Value -eq '') -or ($Value -match '^[\[\]A-Za-z0-9._:-]+:\d{1,5}$') }
        'SPOOF_ARG_STYLE'   { return ($Value -match '^(auto|config|flags|port|none)$') }
        'SPOOF_EXTRA_FLAGS' { return ($Value -notmatch '[;&|$`<>]') }
        'SPOOF_PATH'   { return ($Value -eq '') -or (Test-Path -LiteralPath $Value -PathType Leaf) }
        'WGCF_PATH'    { return ($Value -eq '') -or (Test-Path -LiteralPath $Value -PathType Leaf) }
        'NET_TIMEOUT'  { return ($Value -match '^\d+$') -and ([int]$Value -ge 5) -and ([int]$Value -le 300) }
        'GITHUB_TOKEN' { return ($Value -notmatch '\s') }
    }
    return $false
}

function Get-GitHubHeaders {
    $headers = @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'security-dns-cli' }
    $token = Get-Setting 'GITHUB_TOKEN'
    if ($token) { $headers['Authorization'] = "Bearer $token" }
    return $headers
}

function Write-Pause { [void](Read-Host (T 'press_enter')) }

function Find-FreePort([int]$Start) {
    for ($p = $Start; $p -le [Math]::Min($Start + 200, 65535); $p++) {
        if (-not (Test-PortInUse $p)) { return $p }
    }
    throw "No free port was found near $Start."
}

# -----------------------------------------------------------------------------
# Smart recovery: classify an error, explain it, offer a fix, then retry.
# -----------------------------------------------------------------------------
function Invoke-Native([string]$File, [string[]]$Arguments) {
    $ErrorActionPreference = 'Continue'
    $text = (& $File @Arguments 2>&1 | ForEach-Object { "$_" }) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "$([IO.Path]::GetFileName($File)) failed (exit code $LASTEXITCODE): $text"
    }
    return $text
}

function Get-ProblemKind([string]$Text) {
    $t = $Text.ToLowerInvariant()
    if ($t -match 'conflict:(warp|wireguard)') { return 'conflict' }
    if ($t -match 'doh-unsupported') { return 'doh_unsupported' }
    if ($t -match 'only one usage of each socket|address already in use|already in use') { return 'port_in_use' }
    if ($t -match 'flag provided but not defined|unknown flag|unknown option|unrecognized option') { return 'unsupported_flag' }
    if ($t -match 'no .* asset found') { return 'no_asset' }
    if ($t -match 'rate limit|\(403\)|403 forbidden|\(429\)') { return 'ratelimit' }
    if ($t -match 'timed out|timeout|could not be resolved|no such host is known|unable to connect|connection refused|network is unreachable|the remote name') { return 'network' }
    if ($t -match 'access is denied|permission denied|unauthorizedaccess|operation not permitted') { return 'permission' }
    return 'unknown'
}

function Show-Problem([string]$Kind, [string]$Details) {
    Write-Host ''
    Write-Host ('== ' + (T "p_${Kind}_t") + ' ==') -ForegroundColor Yellow
    Write-Host (T 'pd_what')
    Write-Host ('  ' + (T "p_${Kind}_e"))
    Write-Host (T 'pd_prop')
    Write-Host ('  ' + (T "p_${Kind}_f"))
    Write-Host (T 'pd_details')
    @($Details -split "`n" | Select-Object -Last 6) | ForEach-Object { Write-Host "    $_" }
    $choice = (Read-Host (T 'pd_choose')).Trim().ToLowerInvariant()
    if ($choice -eq 'a') { return 'apply' }
    return 'cancel'
}

function Switch-ArgStyle {
    $next = switch (Get-Setting 'SPOOF_ARG_STYLE') {
        'auto'   { 'config' }
        'config' { 'flags' }
        'flags'  { 'port' }
        'port'   { 'none' }
        default  { 'auto' }
    }
    Set-Setting 'SPOOF_ARG_STYLE' $next
    Write-Good "SpoofDPI argument style: $next"
}

# Returns 'resume' to retry the operation or 'stop' to give up.
function Invoke-Fix([string]$Kind, [string]$Details) {
    switch ($Kind) {
        'port_in_use' {
            $new = Find-FreePort ([int](Get-Setting 'SPOOF_PORT') + 1)
            Set-Setting 'SPOOF_PORT' "$new"
            Write-Good ((T 'port_switched') -f $new)
        }
        'unsupported_flag' { Switch-ArgStyle }
        'network' {
            $seconds = [Math]::Min(120, 2 * [int](Get-Setting 'NET_TIMEOUT'))
            Set-Setting 'NET_TIMEOUT' "$seconds"
            Start-Sleep -Seconds 3
        }
        'ratelimit' { Start-Sleep -Seconds 30 }
        'permission' { if (-not (Test-Administrator)) { return 'stop' } }
        'conflict' {
            if ($Details -match '(?i)conflict:(warp|wireguard)') {
                if ($Matches[1] -eq 'warp') { Stop-WarpTool } else { Stop-WgTool }
            } else { return 'stop' }
        }
        'no_asset' { Show-SettingsMenu; return 'stop' }
        'doh_unsupported' { $Script:SkipSystemDns = $true }
        default { }
    }
    return 'resume'
}

# Runs an operation with smart recovery. Returns $true when it finally succeeds.
function Invoke-Guarded([scriptblock]$Operation) {
    $tried = @{}
    while ($true) {
        try {
            & $Operation
            return $true
        }
        catch {
            $details = $_.Exception.Message
            $kind = Get-ProblemKind $details
            $tried[$kind] = 1 + [int]$tried[$kind]
            if ($tried[$kind] -gt 3) { Write-Caution (T 'giving_up'); return $false }

            if ((Show-Problem -Kind $kind -Details $details) -eq 'cancel') {
                Write-Caution (T 'cancelled'); return $false
            }
            try { $outcome = Invoke-Fix -Kind $kind -Details $details }
            catch {
                Write-Caution (T 'fix_failed'); Write-Caution $_.Exception.Message; return $false
            }
            if ($outcome -eq 'stop') { Write-Caution (T 'cancelled'); return $false }
            Write-Good (T 'fix_applied')
        }
    }
}

# -----------------------------------------------------------------------------
# Encrypted DNS (DNS-over-HTTPS) with leak protection
# -----------------------------------------------------------------------------
function Set-SecureDns {
    $info = Test-DohSupported
    if (-not $info.Supported) {
        if ($Script:SkipSystemDns) { Write-Caution (T 'doh_skipped'); return $false }
        throw "doh-unsupported: Windows build $($info.Build) needs $MinDohBuild or newer."
    }

    $servers  = @((Get-Setting 'DNS_SERVERS').Trim() -split '\s+' | Where-Object { $_ })
    $template = Get-Setting 'DOH_TEMPLATE'
    foreach ($address in $servers) {
        Remove-DnsClientDohServerAddress -ServerAddress $address -ErrorAction SilentlyContinue
        Add-DnsClientDohServerAddress -ServerAddress $address -DohTemplate $template `
            -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
    }
    Write-Good 'DNS-over-HTTPS templates registered.'

    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $servers
        Write-Good "DNS-over-HTTPS enabled on '$($adapter.Name)'"
    }
    Clear-DnsClientCache
    return $true
}

# Backs up the original settings once, and makes sure encrypted DNS is applied.
function Initialize-System {
    Save-PreInstallState
    if (((Get-StateValue 'DNS_RESTORED') -eq $true) -or (-not (Get-StateValue 'DNS_APPLIED'))) {
        $applied = Set-SecureDns
        Set-StateValue 'DNS_APPLIED' ([bool]$applied)
        Set-StateValue 'DNS_RESTORED' $false
    }
}

# -----------------------------------------------------------------------------
# Tool 1: SpoofDPI
# -----------------------------------------------------------------------------
function Get-SpoofExePath {
    $custom = Get-Setting 'SPOOF_PATH'
    if ($custom) { return $custom }
    return $SpoofExe
}
function Test-SpoofInstalled { return (Test-Path -LiteralPath (Get-SpoofExePath)) }
function Test-SpoofRunning {
    $name = [IO.Path]::GetFileNameWithoutExtension((Get-SpoofExePath))
    return [bool](Get-Process -Name $name -ErrorAction SilentlyContinue)
}
function Test-SpoofEnabled { return (Test-Path -LiteralPath $StartupScript) }

function Get-SpoofStyle {
    $style = Get-Setting 'SPOOF_ARG_STYLE'
    if ($style -ne 'auto') { return $style }
    $help = ''
    try {
        $ErrorActionPreference = 'Continue'
        $help = (& (Get-SpoofExePath) '--help' 2>&1 | ForEach-Object { "$_" }) -join ' '
    } catch { $help = '' }
    if ($help -match '(^|\s)-config(\s|=|$)') { return 'config' }
    if (($help -match '(^|\s)-addr(\s|=|$)') -and ($help -match '(^|\s)-port(\s|=|$)')) { return 'flags' }
    if ($help -match '(^|\s)-port(\s|=|$)') { return 'port' }
    return 'none'
}

# Builds without a port option are fixed to 8080.
function Get-SpoofPort {
    if ((Get-SpoofStyle) -eq 'none') { return 8080 }
    return [int](Get-Setting 'SPOOF_PORT')
}

function Get-SpoofDpiArgs([int]$Port) {
    $parts = @()
    switch (Get-SpoofStyle) {
        'config' {
            $configFile = Join-Path $AppDir 'spoofdpi.toml'
            Set-Content -LiteralPath $configFile -Value "[app]`r`nlisten-addr = `"127.0.0.1:$Port`"`r`n" -Encoding ASCII
            $parts += "--config `"$configFile`""
        }
        'flags' { $parts += "--addr 127.0.0.1 --port $Port" }
        'port'  { $parts += "--port $Port" }
        default { }
    }
    $extra = Get-Setting 'SPOOF_EXTRA_FLAGS'
    if ($extra) { $parts += $extra }
    return ($parts -join ' ').Trim()
}

function Install-Spoof {
    $custom = Get-Setting 'SPOOF_PATH'
    if ($custom -and (Test-Path -LiteralPath $custom)) {
        Write-Good "Using your own SpoofDPI program: $custom"
        return
    }
    Install-SpoofDpiBinary
}

function Stop-SpoofProcess {
    $name = [IO.Path]::GetFileNameWithoutExtension((Get-SpoofExePath))
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Install-StartupLauncher([int]$Port) {
    $argsVbs = (Get-SpoofDpiArgs -Port $Port).Replace('"', '""')
    $exe = Get-SpoofExePath
    $launcher = @"
' Security DNS - hidden launcher for SpoofDPI. Managed by Security DNS.
Set shell = CreateObject("WScript.Shell")
shell.Run """$exe"" $argsVbs", 0, False
"@
    New-Item -ItemType Directory -Path (Split-Path -Parent $StartupScript) -Force | Out-Null
    Set-Content -LiteralPath $StartupScript -Value $launcher -Encoding ASCII
}

function Start-SpoofTool {
    if (-not (Test-SpoofInstalled)) { throw 'spoofdpi: program not found (not installed)' }
    Initialize-System
    Stop-SpoofProcess
    $port = Get-SpoofPort
    if (Test-PortInUse $port) {
        if ((Get-SpoofStyle) -eq 'none') {
            throw "This SpoofDPI build cannot change its port, and port $port is occupied. Free that port and try again."
        }
        Write-Caution ((T 'port_busy') -f $port)
        $port = Find-FreePort ($port + 1)
        Set-Setting 'SPOOF_PORT' "$port"
        Write-Good ((T 'port_switched') -f $port)
    }

    $logDir = Join-Path $AppDir 'logs'
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    $outLog = Join-Path $logDir 'spoofdpi.out.log'
    $errLog = Join-Path $logDir 'spoofdpi.err.log'
    Remove-Item -LiteralPath $outLog, $errLog -Force -ErrorAction SilentlyContinue

    $startArgs = @{ FilePath = (Get-SpoofExePath); WindowStyle = 'Hidden'; PassThru = $true
                    RedirectStandardOutput = $outLog; RedirectStandardError = $errLog }
    $argLine = Get-SpoofDpiArgs -Port $port
    if ($argLine) { $startArgs['ArgumentList'] = $argLine }
    $proc = Start-Process @startArgs

    Start-Sleep -Seconds 2
    for ($i = 0; $i -lt 20; $i++) {
        if ($proc.HasExited) { break }
        if (Test-PortInUse $port) {
            Write-Good ((T 'start_ok') -f $port)
            Set-SystemProxy -Port $port
            return
        }
        Start-Sleep -Milliseconds 750
    }

    Write-Caution (T 'start_fail')
    $logText = ''
    foreach ($file in @($errLog, $outLog)) {
        if (Test-Path -LiteralPath $file) { $logText += [string](Get-Content -LiteralPath $file -Raw -ErrorAction SilentlyContinue) }
    }
    throw "SpoofDPI did not start. $logText"
}

function Stop-SpoofTool { Disable-SystemProxy; Stop-SpoofProcess }
function Enable-SpoofTool {
    if (-not (Test-SpoofInstalled)) { throw 'spoofdpi: program not found (not installed)' }
    Install-StartupLauncher -Port (Get-SpoofPort)
}
function Disable-SpoofTool { Remove-StartupLauncher }
function Uninstall-SpoofTool { Stop-SpoofTool; Invoke-RemoveTool 'spoofdpi' }

# -----------------------------------------------------------------------------
# Tool 2: Cloudflare WARP
# -----------------------------------------------------------------------------
function Test-WarpInstalled { return (Test-Path -LiteralPath $WarpCli) }
function Test-WarpRunning {
    if (-not (Test-WarpInstalled)) { return $false }
    $status = (& $WarpCli --accept-tos status 2>$null) -join ' '
    return ($status -match 'Status update:\s*Connected')
}
function Test-WarpEnabled {
    $svc = Get-Service -Name 'CloudflareWARP' -ErrorAction SilentlyContinue
    return [bool]($svc -and ($svc.StartType -eq 'Automatic'))
}

function Start-WarpTool {
    if (-not (Test-WarpInstalled)) { throw 'warp-cli: program not found (not installed)' }
    if (Test-WgRunning) { throw 'CONFLICT:wireguard - WireGuard is running; WARP cannot start at the same time.' }
    Initialize-System
    Install-WarpClient
    & $WarpCli --accept-tos connect *> $null
    for ($i = 0; $i -lt 20; $i++) {
        if (Test-WarpRunning) { Write-Good 'Cloudflare WARP is connected.'; return }
        Start-Sleep -Seconds 1
    }
    throw 'WARP did not report Connected (connection timed out). Check: warp-cli status'
}

function Stop-WarpTool { Disconnect-Warp }
function Enable-WarpTool {
    if (-not (Test-WarpInstalled)) { throw 'warp-cli: program not found (not installed)' }
    Set-Service -Name 'CloudflareWARP' -StartupType Automatic
}
function Disable-WarpTool {
    $svc = Get-Service -Name 'CloudflareWARP' -ErrorAction SilentlyContinue
    if ($svc) { Set-Service -Name 'CloudflareWARP' -StartupType Manual }
}
function Uninstall-WarpTool { Stop-WarpTool; Invoke-RemoveTool 'warp' }

# -----------------------------------------------------------------------------
# Tool 3: WireGuard with a WARP profile made by wgcf
# -----------------------------------------------------------------------------
function Get-WgService { return (Get-Service -Name ('WireGuardTunnel$' + $WgTunnelName) -ErrorAction SilentlyContinue) }
function Test-WgInstalled { return ((Test-Path -LiteralPath $WgExe) -and (Test-Path -LiteralPath $WgConf)) }
function Test-WgRunning {
    $svc = Get-WgService
    return [bool]($svc -and ($svc.Status -eq 'Running'))
}
function Test-WgEnabled {
    $svc = Get-WgService
    return [bool]($svc -and ($svc.StartType -eq 'Automatic'))
}

function Get-WgcfPath {
    $custom = Get-Setting 'WGCF_PATH'
    if ($custom) { return $custom }
    return $WgcfExe
}

# Builds the active profile from the wgcf profile plus your Settings.
function Update-WgConf {
    $source = Join-Path $WgcfDir 'wgcf-profile.conf'
    if (-not (Test-Path -LiteralPath $source)) { throw "WireGuard profile is missing: $source" }
    $endpoint = Get-Setting 'WG_ENDPOINT'
    $lines = @(Get-Content -LiteralPath $source)
    if ($endpoint) {
        $lines = @($lines | ForEach-Object { if ($_ -match '^\s*Endpoint\s*=') { "Endpoint = $endpoint" } else { $_ } })
    }
    Set-Content -LiteralPath $WgConf -Value $lines -Encoding ASCII
    Set-StateValue 'WG_CONF_ADDED' $true
}

function Install-Wg {
    Install-WireGuardClient
    if (-not (Get-Setting 'WGCF_PATH')) { Install-Wgcf }
    New-Item -ItemType Directory -Path $WgcfDir -Force | Out-Null
    $exe = Get-WgcfPath
    Push-Location $WgcfDir
    try {
        if (-not (Test-Path -LiteralPath 'wgcf-account.toml')) { [void](Invoke-Native $exe @('register', '--accept-tos')) }
        if (-not (Test-Path -LiteralPath 'wgcf-profile.conf')) { [void](Invoke-Native $exe @('generate')) }
    }
    finally { Pop-Location }
    Update-WgConf
    Write-Good "WireGuard profile ready at $WgConf"
}

function Start-WgTool {
    if (-not (Test-WgInstalled)) { throw 'wireguard: program not found (WireGuard is not installed)' }
    if (Test-WarpRunning) { throw 'CONFLICT:warp - WARP is connected; WireGuard cannot start at the same time.' }
    Initialize-System
    if (Get-WgService) { & $WgExe /uninstalltunnelservice $WgTunnelName *> $null; Start-Sleep -Seconds 1 }
    Update-WgConf
    [void](Invoke-Native $WgExe @('/installtunnelservice', $WgConf))
    for ($i = 0; $i -lt 15; $i++) {
        if (Test-WgRunning) { Write-Good 'WireGuard tunnel started.'; return }
        Start-Sleep -Seconds 1
    }
    throw 'WireGuard tunnel did not start (connection timed out).'
}

function Stop-WgTool {
    if ((Test-Path -LiteralPath $WgExe) -and (Get-WgService)) {
        & $WgExe /uninstalltunnelservice $WgTunnelName *> $null
    }
}
function Enable-WgTool {
    $svc = Get-WgService
    if ($svc) { Set-Service -InputObject $svc -StartupType Automatic }
    else { Write-Caution 'Start the tunnel first; its service then starts automatically at boot.' }
}
function Disable-WgTool {
    $svc = Get-WgService
    if ($svc) { Set-Service -InputObject $svc -StartupType Manual }
}
function Uninstall-WgTool { Stop-WgTool; Invoke-RemoveTool 'wireguard' }

# -----------------------------------------------------------------------------
# Tool dispatcher, quick modes, kill switch, restore
# -----------------------------------------------------------------------------
$ToolFns = @{
    spoofdpi  = @{ install = 'Install-Spoof'; start = 'Start-SpoofTool'; stop = 'Stop-SpoofTool'; enable = 'Enable-SpoofTool'
                   disable = 'Disable-SpoofTool'; uninstall = 'Uninstall-SpoofTool'
                   installed = 'Test-SpoofInstalled'; running = 'Test-SpoofRunning'; enabled = 'Test-SpoofEnabled' }
    warp      = @{ install = 'Install-WarpClient'; start = 'Start-WarpTool'; stop = 'Stop-WarpTool'; enable = 'Enable-WarpTool'
                   disable = 'Disable-WarpTool'; uninstall = 'Uninstall-WarpTool'
                   installed = 'Test-WarpInstalled'; running = 'Test-WarpRunning'; enabled = 'Test-WarpEnabled' }
    wireguard = @{ install = 'Install-Wg'; start = 'Start-WgTool'; stop = 'Stop-WgTool'; enable = 'Enable-WgTool'
                   disable = 'Disable-WgTool'; uninstall = 'Uninstall-WgTool'
                   installed = 'Test-WgInstalled'; running = 'Test-WgRunning'; enabled = 'Test-WgEnabled' }
}

function Invoke-ToolAction([string]$Tool, [string]$Action) { & $ToolFns[$Tool][$Action] }
function Test-ToolState([string]$Tool, [string]$State) { return [bool](& $ToolFns[$Tool][$State]) }

# Quick mode: start one tool, stop the others (installing it first if needed).
function Invoke-Preset([int]$Mode) {
    switch ($Mode) {
        1 { Stop-WgTool; Stop-WarpTool; if (-not (Test-SpoofInstalled)) { Install-Spoof }; Start-SpoofTool }
        2 { Stop-SpoofTool; Stop-WgTool; if (-not (Test-WarpInstalled)) { Install-WarpClient }; Start-WarpTool }
        3 { Stop-SpoofTool; Stop-WarpTool; if (-not (Test-WgInstalled)) { Install-Wg }; Start-WgTool }
    }
}

function Confirm-Tunnel {
    Write-Host ''
    Write-Caution (T 'tunnel_warn')
    Write-Host ''
    return (Confirm-Action (T 'continue_q'))
}

# Stops every tool at once. Best effort, no prompts, so it is fast and reliable.
function Invoke-KillSwitch {
    Write-Step (T 'kill_start')
    $failed = $false
    foreach ($operation in @({ Disable-SystemProxy }, { Stop-WgTool }, { Stop-WarpTool }, { Stop-SpoofProcess })) {
        try { & $operation } catch { $failed = $true; Write-Caution $_.Exception.Message }
    }
    if ((Test-SpoofRunning) -or (Test-WarpRunning) -or (Test-WgRunning)) { $failed = $true }
    try { Initialize-System } catch { $failed = $true; Write-Caution $_.Exception.Message }
    if ($failed) { Write-Caution (T 'kill_partial') } else { Write-Good (T 'kill_done') }
}

function Get-UninstallScript {
    if (Test-Path -LiteralPath $AppUninstall) { return $AppUninstall }
    $remote = Join-Path $env:TEMP 'security-dns-uninstall.ps1'
    Invoke-WebRequest -Uri "$RepoRaw/uninstall.ps1" -OutFile $remote -UseBasicParsing
    return $remote
}

function Invoke-RemoveTool([string]$Tool) { & (Get-UninstallScript) -Tool $Tool }

function Invoke-RestoreOriginal {
    if (Confirm-Action (T 'restore_q')) {
        try { & (Get-UninstallScript) -RestoreOnly; Write-Good (T 'restore_done') }
        catch { Write-Caution (T 'restore_fail'); Write-Caution $_.Exception.Message }
    }
}

function Invoke-Uninstaller { & (Get-UninstallScript) }

# -----------------------------------------------------------------------------
# Status
# -----------------------------------------------------------------------------
function Write-ToolStatus([string]$Tool, [string]$Label) {
    if (Test-ToolState $Tool 'installed') {
        $parts = @((T 'st_installed'))
        $parts += $(if (Test-ToolState $Tool 'running') { T 'st_running' } else { T 'st_stopped' })
        $parts += $(if (Test-ToolState $Tool 'enabled') { T 'st_enabled' } else { T 'st_disabled' })
    } else { $parts = @((T 'st_missing')) }
    Write-Host ('  {0,-12} : {1}' -f $Label, ($parts -join ', '))
}

function Show-Status {
    Write-Host ''
    Write-ToolStatus 'spoofdpi' 'SpoofDPI'
    Write-ToolStatus 'warp' 'WARP'
    Write-ToolStatus 'wireguard' 'WireGuard'
    $dns = if ((Get-StateValue 'DNS_APPLIED') -eq $true -and -not ((Get-StateValue 'DNS_RESTORED') -eq $true)) { 'DNS-over-HTTPS' } else { '-' }
    Write-Host ('  {0,-12} : {1}' -f (T 'stat_dns'), $dns)
    Write-Host ''
}

# -----------------------------------------------------------------------------
# Updates
# -----------------------------------------------------------------------------
function Invoke-UpdateCheck {
    Write-Step 'Security DNS script'
    try {
        $remoteText = (Invoke-WebRequest -Uri "$RepoRaw/install.ps1" -UseBasicParsing).Content.TrimStart([char]0xFEFF)
        $match = [regex]::Match($remoteText, "ScriptVersion\s*=\s*'([^']+)'")
        $remoteVersion = if ($match.Success) { $match.Groups[1].Value } else { '' }
        if (-not $remoteVersion) { Write-Caution 'Could not read the remote script version.' }
        elseif ($remoteVersion -ne $ScriptVersion) {
            if (Confirm-Action "Update the script from $ScriptVersion to $remoteVersion?") {
                [void][scriptblock]::Create($remoteText)
                $newUninstall = (Invoke-WebRequest -Uri "$RepoRaw/uninstall.ps1" -UseBasicParsing).Content.TrimStart([char]0xFEFF)
                [void][scriptblock]::Create($newUninstall)
                Set-Content -LiteralPath $AppScript -Value $remoteText -Encoding UTF8
                Set-Content -LiteralPath $AppUninstall -Value $newUninstall -Encoding UTF8
                Write-Good "Script updated to $remoteVersion. Reopen the menu to use it."
            }
        } else { Write-Good "Script is up to date ($ScriptVersion)." }
    }
    catch { Write-Caution "Script update check failed: $($_.Exception.Message)" }

    if (Test-SpoofInstalled) {
        Write-Step 'SpoofDPI'
        $wasRunning = Test-SpoofRunning
        if ((Invoke-Guarded { Install-Spoof }) -and $wasRunning) { [void](Invoke-Guarded { Start-SpoofTool }) }
    }
    if ((Test-Path -LiteralPath (Get-WgcfPath)) -and -not (Get-Setting 'WGCF_PATH')) {
        Write-Step 'wgcf'
        [void](Invoke-Guarded { Install-Wgcf })
    }
    if (Test-WarpInstalled) { Write-Step 'Cloudflare WARP'; Write-Good 'The WARP client updates itself automatically.' }
}

# -----------------------------------------------------------------------------
# First-time installation
# -----------------------------------------------------------------------------
function Install-SecurityDns {
    Write-Host (T 'first_run')
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
    Install-AppFiles
    Set-StateValue 'INSTALLED' $true
    Write-Step 'Backing up your settings and enabling encrypted DNS'
    [void](Invoke-Guarded { Initialize-System })
    Install-Shortcuts
    Write-Host ''
    Write-Good (T 'done_title')
    Write-Host ('  ' + (T 'done_menu'))
    Write-Host ('  ' + (T 'done_next'))
    if (Confirm-Action (T 'first_start_q')) { [void](Invoke-Guarded { Invoke-Preset 1 }) }
}

# -----------------------------------------------------------------------------
# Menus
# -----------------------------------------------------------------------------
function Show-About {
    Write-Host ''
    Write-Host ((T 'about_head') + "  v$ScriptVersion") -ForegroundColor Cyan
    Write-Host ''
    Write-Host ('  ' + ((T 'about_dev') -f $PortfolioUrl))
    Write-Host ('  ' + ((T 'about_mail') -f $ContactEmail))
    Write-Host ('  ' + (T 'about_license'))
    Write-Host ''
    Write-Host ('  ' + (T 'about_sec_title')) -ForegroundColor Cyan
    Write-Host ('  ' + ((T 'about_sec_text') -f $ContactEmail))
    Write-Host ''
    Write-Pause
}

function Show-SettingsMenu {
    while ($true) {
        Write-Host ''
        Write-Host (T 'set_head') -ForegroundColor Cyan
        Write-Host ('  ' + (T 'set_hint'))
        Write-Host ''
        for ($i = 0; $i -lt $SettingKeys.Count; $i++) {
            $key = $SettingKeys[$i]
            $current = Get-Setting $key
            if ($key -eq 'GITHUB_TOKEN' -and $current) { $current = '********' }
            if (-not $current) { $current = '<empty>' }
            Write-Host ('  {0,2}) {1}' -f ($i + 1), (T "set_$key"))
            Write-Host ('      {0}: {1}' -f (T 'set_current'), $current)
        }
        Write-Host ''
        $choice = (Read-Host (T 'choose')).Trim().ToLowerInvariant()
        if ($choice -in @('', 'b', 'q')) { return }
        if ($choice -eq 'r') {
            if (Confirm-Action (T 'set_reset_q')) { Remove-Item -LiteralPath $SettingsFile -Force -ErrorAction SilentlyContinue; Write-Good (T 'set_saved') }
            continue
        }
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $SettingKeys.Count) {
            $key = $SettingKeys[[int]$choice - 1]
            $new = Read-Host (T 'set_prompt')
            if ($new -eq '') { continue }
            if ($new -eq '-') { $new = '' }
            if (Test-SettingValid $key $new) {
                Set-Setting $key $new
                Write-Good (T 'set_saved')
                if ($key -in @('DNS_SERVERS', 'DOH_TEMPLATE') -and ((Get-StateValue 'INSTALLED') -eq $true)) {
                    Set-StateValue 'DNS_RESTORED' $true
                    [void](Invoke-Guarded { Initialize-System })
                }
            } else { Write-Caution (T 'set_invalid') }
        } else { Write-Caution (T 'bad_choice') }
    }
}

function Show-ToolMenu([string]$Tool, [string]$Label) {
    while ($true) {
        Write-Host ''
        Write-Host $Label -ForegroundColor Cyan
        Write-Host ('  ' + (T "tool_$Tool"))
        Write-ToolStatus $Tool $Label
        foreach ($key in @('act_install', 'act_start', 'act_stop', 'act_enable', 'act_disable', 'act_uninstall', 'tm_back')) { Write-Host ('  ' + (T $key)) }
        Write-Host ''
        $choice = (Read-Host (T 'choose')).Trim().ToLowerInvariant()
        $action = switch ($choice) { '1' { 'install' } '2' { 'start' } '3' { 'stop' } '4' { 'enable' } '5' { 'disable' } '6' { 'uninstall' } default { '' } }
        if ($choice -in @('', 'b', 'q')) { return }
        if (-not $action) { Write-Caution (T 'bad_choice'); continue }
        if ($action -eq 'start' -and $Tool -ne 'spoofdpi' -and -not (Confirm-Tunnel)) { continue }
        if ($action -eq 'uninstall' -and -not (Confirm-Action (T 'continue_q'))) { continue }
        if (Invoke-Guarded { Invoke-ToolAction $Tool $action }) { Write-Good (T 'done_ok') }
    }
}

function Install-AllMissing {
    foreach ($tool in @('spoofdpi', 'warp', 'wireguard')) {
        if (-not (Test-ToolState $tool 'installed')) { [void](Invoke-Guarded { Invoke-ToolAction $tool 'install' }) }
    }
}

function Show-ToolManager {
    while ($true) {
        Write-Host ''
        Write-Host (T 'tm_head') -ForegroundColor Cyan
        Write-Host ('  ' + (T 'tm_hint'))
        Show-Status
        Write-Host '  1) SpoofDPI'
        Write-Host '  2) Cloudflare WARP'
        Write-Host '  3) WireGuard (wgcf)'
        foreach ($key in @('tm_all', 'tm_kill', 'tm_back')) { Write-Host ('  ' + (T $key)) }
        Write-Host ''
        switch ((Read-Host (T 'choose')).Trim().ToLowerInvariant()) {
            '1' { Show-ToolMenu 'spoofdpi' 'SpoofDPI' }
            '2' { Show-ToolMenu 'warp' 'Cloudflare WARP' }
            '3' { Show-ToolMenu 'wireguard' 'WireGuard (wgcf)' }
            'i' { Install-AllMissing }
            'k' { Invoke-KillSwitch }
            { $_ -in @('', 'b', 'q') } { return }
            default { Write-Caution (T 'bad_choice') }
        }
    }
}

function Show-MainMenu {
    while ($true) {
        Write-Host ''
        Write-Host ((T 'menu_head') -f $ScriptVersion) -ForegroundColor Cyan
        Write-Host ''
        Write-Host ('  ' + (T 'menu_quick'))
        foreach ($key in @('menu_1', 'menu_2', 'menu_3')) { Write-Host ('  ' + (T $key)) }
        Write-Host ''
        Write-Host ('  ' + (T 'menu_manage'))
        foreach ($key in @('menu_4', 'menu_5', 'menu_6', 'menu_7', 'menu_8', 'menu_9', 'menu_a', 'menu_u', 'menu_q')) { Write-Host ('  ' + (T $key)) }
        Write-Host ''
        switch ((Read-Host (T 'choose')).Trim().ToLowerInvariant()) {
            '1' { if (Invoke-Guarded { Invoke-Preset 1 }) { Write-Good (T 'done_ok') } }
            '2' { if ((Confirm-Tunnel) -and (Invoke-Guarded { Invoke-Preset 2 })) { Write-Good (T 'done_ok') } }
            '3' { if ((Confirm-Tunnel) -and (Invoke-Guarded { Invoke-Preset 3 })) { Write-Good (T 'done_ok') } }
            '4' { Show-ToolManager }
            '5' { Show-SettingsMenu }
            '6' { Show-Status }
            '7' { Invoke-UpdateCheck }
            '8' { Invoke-RestoreOriginal }
            '9' { Invoke-KillSwitch }
            'a' { Show-About }
            'u' { if (Confirm-Action (T 'uninst_q')) { Invoke-Uninstaller; return } }
            'q' { return }
            default { Write-Caution (T 'bad_choice') }
        }
    }
}

# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
if ($Version) { Write-Host $ScriptVersion; return }

if (-not (Test-Administrator)) { throw $Messages.en.need_admin }

if ($Kill)    { $Script:Lang = 'en'; Invoke-KillSwitch; return }
if ($Restore) { $Script:Lang = 'en'; & (Get-UninstallScript) -RestoreOnly; return }

Choose-Language

if ($Uninstall) { Invoke-Uninstaller; return }
if ($Update)    { Invoke-UpdateCheck; return }

if ($Menu -or ((Get-StateValue 'INSTALLED') -eq $true)) {
    Show-MainMenu
} else {
    Install-SecurityDns
    Show-MainMenu
}
