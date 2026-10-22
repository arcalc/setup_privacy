#include "SystemConfig.h"

#include "CommandRunner.h"
#include "Platform.h"
#include "Types.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSysInfo>

#ifdef Q_OS_WIN
#include <QSettings>
#include <windows.h>
#include <wininet.h>
#else
#include <unistd.h>
#endif

namespace sdns {

#ifdef Q_OS_WIN
// =============================================================================
// Windows: DNS-over-HTTPS through PowerShell, proxy through the registry
// =============================================================================
namespace {

const QString kProxyKey = QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
const QStringList kProxyValues = {QStringLiteral("ProxyEnable"), QStringLiteral("ProxyServer"),
                                  QStringLiteral("ProxyOverride"), QStringLiteral("AutoConfigURL")};
constexpr int kMinDohBuild = 19041;

QString quoteList(const QStringList& items)
{
    QStringList quoted;
    for (const QString& item : items) {
        QString safe = item;
        safe.replace(QLatin1Char('\''), QStringLiteral("''"));
        quoted << QStringLiteral("'%1'").arg(safe);
    }
    return quoted.join(QLatin1Char(','));
}

void notifyProxyChanged()
{
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}

int windowsBuild()
{
    const QStringList parts = QSysInfo::kernelVersion().split(QLatin1Char('.'));
    return parts.size() >= 3 ? parts.at(2).toInt() : 0;
}

} // namespace

QJsonObject SystemConfig::snapshot()
{
    QJsonObject o;
    o[QStringLiteral("platform")] = QStringLiteral("windows");

    QJsonObject proxy;
    QSettings reg(kProxyKey, QSettings::NativeFormat);
    for (const QString& name : kProxyValues) {
        QJsonObject entry;
        entry[QStringLiteral("exists")] = reg.contains(name);
        entry[QStringLiteral("value")] = QJsonValue::fromVariant(reg.value(name));
        proxy[name] = entry;
    }
    o[QStringLiteral("proxy")] = proxy;

    const QString script = QStringLiteral(R"PS(
$ErrorActionPreference = 'Stop'
$adapters = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {
  $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex = $($_.ifIndex)"
  [pscustomobject]@{ index = [int]$_.ifIndex; dhcp = [bool]$cfg.DHCPEnabled; servers = @($cfg.DNSServerSearchOrder) }
})
$doh = @()
if (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
  $doh = @(Get-DnsClientDohServerAddress | ForEach-Object {
    [pscustomobject]@{ address = $_.ServerAddress; template = $_.DohTemplate; udp = [bool]$_.AllowFallbackToUdp; auto = [bool]$_.AutoUpgrade }
  })
}
[pscustomobject]@{ adapters = @($adapters); doh = @($doh) } | ConvertTo-Json -Depth 5 -Compress
)PS");
    const CommandResult r = CommandRunner::runPowerShellChecked(script);
    o[QStringLiteral("dns")] = QJsonDocument::fromJson(r.out.trimmed().toUtf8()).object();
    return o;
}

bool SystemConfig::enableEncryptedDns(bool allowSkip)
{
    if (windowsBuild() < kMinDohBuild) {
        if (allowSkip)
            return false;
        throw OperationError(makeProblem(ProblemKind::UnsupportedWindowsBuild,
                                         QStringLiteral("doh-unsupported: Windows build %1 needs %2 or newer")
                                             .arg(windowsBuild()).arg(kMinDohBuild)));
    }
    QString templ = m_s.dohTemplate;
    templ.replace(QLatin1Char('\''), QStringLiteral("''"));
    const QString script = QStringLiteral(R"PS(
$ErrorActionPreference = 'Stop'
$servers = @(%1)
$template = '%2'
foreach ($a in $servers) {
  Remove-DnsClientDohServerAddress -ServerAddress $a -ErrorAction SilentlyContinue
  Add-DnsClientDohServerAddress -ServerAddress $a -DohTemplate $template -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
}
Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {
  Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $servers
}
Clear-DnsClientCache
)PS").arg(quoteList(m_s.dnsServers), templ);
    CommandRunner::runPowerShellChecked(script, 120000);
    return true;
}

bool SystemConfig::isEncryptedDnsActive()
{
    if (windowsBuild() < kMinDohBuild)
        return false;
    QString templ = m_s.dohTemplate;
    templ.replace(QLatin1Char('\''), QStringLiteral("''"));
    const CommandResult r = CommandRunner::runPowerShell(
        QStringLiteral("@(Get-DnsClientDohServerAddress | Where-Object { $_.DohTemplate -eq '%1' }).Count").arg(templ));
    return r.ok() && r.out.trimmed().toInt() > 0;
}

void SystemConfig::enableProxy(int port)
{
    QSettings reg(kProxyKey, QSettings::NativeFormat);
    reg.remove(QStringLiteral("AutoConfigURL"));
    reg.setValue(QStringLiteral("ProxyServer"), QStringLiteral("127.0.0.1:%1").arg(port));
    reg.setValue(QStringLiteral("ProxyOverride"), QStringLiteral("localhost;127.*;10.*;192.168.*;<local>"));
    reg.setValue(QStringLiteral("ProxyEnable"), 1);
    reg.sync();
    notifyProxyChanged();
}

void SystemConfig::disableProxy()
{
    QSettings reg(kProxyKey, QSettings::NativeFormat);
    reg.setValue(QStringLiteral("ProxyEnable"), 0);
    reg.sync();
    notifyProxyChanged();
}

void SystemConfig::restore(const QJsonObject& snap)
{
    // Proxy values
    {
        QSettings reg(kProxyKey, QSettings::NativeFormat);
        const QJsonObject proxy = snap.value(QStringLiteral("proxy")).toObject();
        for (const QString& name : kProxyValues) {
            const QJsonObject entry = proxy.value(name).toObject();
            if (entry.value(QStringLiteral("exists")).toBool()) {
                const QVariant v = entry.value(QStringLiteral("value")).toVariant();
                if (name == QLatin1String("ProxyEnable"))
                    reg.setValue(name, v.toInt());
                else
                    reg.setValue(name, v.toString());
            } else {
                reg.remove(name);
            }
        }
        reg.sync();
        notifyProxyChanged();
    }

    // DNS and DoH entries
    const QJsonObject dns = snap.value(QStringLiteral("dns")).toObject();
    const QString json = QString::fromUtf8(QJsonDocument(dns).toJson(QJsonDocument::Compact));
    const QString script = QStringLiteral(R"PS(
$ErrorActionPreference = 'Stop'
$data = @'
%1
'@ | ConvertFrom-Json
foreach ($a in @(%2)) { Remove-DnsClientDohServerAddress -ServerAddress $a -ErrorAction SilentlyContinue }
foreach ($e in @($data.doh)) {
  Add-DnsClientDohServerAddress -ServerAddress $e.address -DohTemplate $e.template -AllowFallbackToUdp ([bool]$e.udp) -AutoUpgrade ([bool]$e.auto) | Out-Null
}
foreach ($e in @($data.adapters)) {
  if ($e.dhcp -or -not $e.servers) { Set-DnsClientServerAddress -InterfaceIndex $e.index -ResetServerAddresses }
  else { Set-DnsClientServerAddress -InterfaceIndex $e.index -ServerAddresses @($e.servers) }
}
Clear-DnsClientCache
)PS").arg(json, quoteList(m_s.dnsServers));
    CommandRunner::runPowerShellChecked(script, 120000);
}

#else
// =============================================================================
// Linux: systemd-resolved (DNS-over-TLS), /etc/environment, GNOME, KDE
// =============================================================================
namespace {

const QString kResolvConf = QStringLiteral("/etc/resolv.conf");
const QString kDropIn = QStringLiteral("/etc/systemd/resolved.conf.d/90-security-dns.conf");
const QString kStub = QStringLiteral("/run/systemd/resolve/stub-resolv.conf");
const QString kEnvFile = QStringLiteral("/etc/environment");
const QString kBegin = QStringLiteral("# BEGIN security-dns");
const QString kEnd = QStringLiteral("# END security-dns");

const QList<QStringList> kGnomeKeys = {
    {QStringLiteral("org.gnome.system.proxy"), QStringLiteral("mode")},
    {QStringLiteral("org.gnome.system.proxy"), QStringLiteral("autoconfig-url")},
    {QStringLiteral("org.gnome.system.proxy"), QStringLiteral("ignore-hosts")},
    {QStringLiteral("org.gnome.system.proxy.http"), QStringLiteral("host")},
    {QStringLiteral("org.gnome.system.proxy.http"), QStringLiteral("port")},
    {QStringLiteral("org.gnome.system.proxy.https"), QStringLiteral("host")},
    {QStringLiteral("org.gnome.system.proxy.https"), QStringLiteral("port")}};

struct DesktopUser {
    QString name;
    QString home;
    uid_t uid = 0;
    gid_t gid = 0;
};

// Regular users: UID 1000 to 65533 with a home folder under /home.
QList<DesktopUser> desktopUsers()
{
    QList<DesktopUser> users;
    QFile passwd(QStringLiteral("/etc/passwd"));
    if (!passwd.open(QIODevice::ReadOnly | QIODevice::Text))
        return users;
    while (!passwd.atEnd()) {
        const QStringList f = QString::fromUtf8(passwd.readLine()).trimmed().split(QLatin1Char(':'));
        if (f.size() < 6)
            continue;
        const uint uid = f.at(2).toUInt();
        if (uid >= 1000 && uid < 65534 && f.at(5).startsWith(QLatin1String("/home/"))) {
            DesktopUser u;
            u.name = f.at(0);
            u.uid = uid;
            u.gid = f.at(3).toUInt();
            u.home = f.at(5);
            users.append(u);
        }
    }
    return users;
}

QByteArray readAll(const QString& path)
{
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

void writeAll(const QString& path, const QByteArray& data)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        throw OperationError(makeProblem(ProblemKind::PermissionDenied,
                                         QStringLiteral("Permission denied: cannot write %1").arg(path)));
    f.write(data);
}

// Records whether a path is a symlink, a regular file (with contents), or absent.
QJsonObject snapshotPath(const QString& path)
{
    QJsonObject o;
    const QFileInfo info(path);
    if (info.isSymLink()) {
        o[QStringLiteral("kind")] = QStringLiteral("link");
        o[QStringLiteral("target")] = QFile::symLinkTarget(path);
    } else if (info.exists()) {
        o[QStringLiteral("kind")] = QStringLiteral("file");
        o[QStringLiteral("data")] = QString::fromLatin1(readAll(path).toBase64());
    } else {
        o[QStringLiteral("kind")] = QStringLiteral("absent");
    }
    return o;
}

void restorePath(const QString& path, const QJsonObject& snap)
{
    const QString kind = snap.value(QStringLiteral("kind")).toString();
    if (kind.isEmpty())
        return;
    QFile::remove(path);
    if (kind == QLatin1String("link"))
        QFile::link(snap.value(QStringLiteral("target")).toString(), path);
    else if (kind == QLatin1String("file"))
        writeAll(path, QByteArray::fromBase64(snap.value(QStringLiteral("data")).toString().toLatin1()));
}

CommandResult runGsettings(const DesktopUser& user, const QStringList& gsettingsArgs)
{
    const QString bus = QStringLiteral("/run/user/%1/bus").arg(user.uid);
    if (!QFileInfo::exists(bus) || platform::findTool(QStringLiteral("gsettings")).isEmpty())
        return CommandResult();
    QStringList args = {QStringLiteral("-u"), user.name, QStringLiteral("--"), QStringLiteral("env"),
                        QStringLiteral("DBUS_SESSION_BUS_ADDRESS=unix:path=") + bus, QStringLiteral("gsettings")};
    args += gsettingsArgs;
    return CommandRunner::run(QStringLiteral("runuser"), args, 8000);
}

QString kwriteconfig()
{
    QString p = platform::findTool(QStringLiteral("kwriteconfig6"));
    return p.isEmpty() ? platform::findTool(QStringLiteral("kwriteconfig5")) : p;
}

void runKde(const DesktopUser& user, const QString& key, const QString& value)
{
    const QString tool = kwriteconfig();
    if (tool.isEmpty())
        return;
    CommandRunner::run(QStringLiteral("runuser"),
                       {QStringLiteral("-u"), user.name, QStringLiteral("--"), tool, QStringLiteral("--file"),
                        QStringLiteral("kioslaverc"), QStringLiteral("--group"), QStringLiteral("Proxy Settings"),
                        QStringLiteral("--key"), key, value},
                       8000);
}

// Rewrites the managed block in /etc/environment. port <= 0 removes the block.
void writeEnvBlock(int port)
{
    const QStringList lines = QString::fromUtf8(readAll(kEnvFile)).split(QLatin1Char('\n'));
    QStringList out;
    bool skipping = false;
    for (const QString& line : lines) {
        if (line == kBegin) { skipping = true; continue; }
        if (line == kEnd) { skipping = false; continue; }
        if (!skipping)
            out << line;
    }
    while (!out.isEmpty() && out.last().isEmpty())
        out.removeLast();
    if (port > 0) {
        const QString url = QStringLiteral("http://127.0.0.1:%1").arg(port);
        out << kBegin
            << QStringLiteral("http_proxy=") + url << QStringLiteral("https_proxy=") + url
            << QStringLiteral("HTTP_PROXY=") + url << QStringLiteral("HTTPS_PROXY=") + url
            << QStringLiteral("no_proxy=localhost,127.0.0.1,::1") << QStringLiteral("NO_PROXY=localhost,127.0.0.1,::1")
            << kEnd;
    }
    writeAll(kEnvFile, (out.join(QLatin1Char('\n')) + QLatin1Char('\n')).toUtf8());
}

} // namespace

QJsonObject SystemConfig::snapshot()
{
    QJsonObject o;
    o[QStringLiteral("platform")] = QStringLiteral("linux");
    o[QStringLiteral("resolv")] = snapshotPath(kResolvConf);
    o[QStringLiteral("dropin")] = snapshotPath(kDropIn);
    o[QStringLiteral("env")] = snapshotPath(kEnvFile);

    QJsonObject gnome;
    QJsonObject kde;
    for (const DesktopUser& user : desktopUsers()) {
        QJsonObject values;
        for (const QStringList& key : kGnomeKeys) {
            const CommandResult r = runGsettings(user, {QStringLiteral("get"), key.at(0), key.at(1)});
            if (r.ok())
                values[key.at(0) + QLatin1Char(' ') + key.at(1)] = r.out.trimmed();
        }
        if (!values.isEmpty())
            gnome[user.name] = values;
        kde[user.name] = snapshotPath(user.home + QStringLiteral("/.config/kioslaverc"));
    }
    o[QStringLiteral("gnome")] = gnome;
    o[QStringLiteral("kde")] = kde;
    return o;
}

bool SystemConfig::enableEncryptedDns(bool)
{
    if (platform::findTool(QStringLiteral("resolvectl")).isEmpty())
        throw OperationError(makeProblem(ProblemKind::ResolvedMissing,
                                         QStringLiteral("resolvectl: command not found (systemd-resolved is missing)")));
    CommandRunner::runChecked(QStringLiteral("systemctl"),
                              {QStringLiteral("enable"), QStringLiteral("--now"), QStringLiteral("systemd-resolved")});

    // A drop-in file overrides resolved.conf, so undoing it only means deleting this file.
    const QString conf = QStringLiteral("# Managed by Security DNS. Removed by Restore.\n[Resolve]\nDNS=%1\n"
                                        "FallbackDNS=\nDNSOverTLS=yes\nDNSSEC=allow-downgrade\nDomains=~.\n")
                             .arg(m_s.dnsServers.join(QLatin1Char(' ')));
    writeAll(kDropIn, conf.toUtf8());

    if (!QFileInfo::exists(kStub))
        throw OperationError(makeProblem(ProblemKind::ResolvedMissing,
                                         QStringLiteral("systemd-resolved stub file not found at %1").arg(kStub)));
    QFile::remove(kResolvConf);
    QFile::link(kStub, kResolvConf);
    CommandRunner::runChecked(QStringLiteral("systemctl"), {QStringLiteral("restart"), QStringLiteral("systemd-resolved")});
    return true;
}

bool SystemConfig::isEncryptedDnsActive()
{
    return QString::fromUtf8(readAll(kDropIn)).contains(QStringLiteral("DNSOverTLS=yes"));
}

void SystemConfig::enableProxy(int port)
{
    writeEnvBlock(port);
    const QString url = QStringLiteral("http://127.0.0.1:%1").arg(port);
    for (const DesktopUser& user : desktopUsers()) {
        const QString portText = QString::number(port);
        runGsettings(user, {QStringLiteral("set"), QStringLiteral("org.gnome.system.proxy"), QStringLiteral("mode"), QStringLiteral("manual")});
        runGsettings(user, {QStringLiteral("set"), QStringLiteral("org.gnome.system.proxy.http"), QStringLiteral("host"), QStringLiteral("127.0.0.1")});
        runGsettings(user, {QStringLiteral("set"), QStringLiteral("org.gnome.system.proxy.http"), QStringLiteral("port"), portText});
        runGsettings(user, {QStringLiteral("set"), QStringLiteral("org.gnome.system.proxy.https"), QStringLiteral("host"), QStringLiteral("127.0.0.1")});
        runGsettings(user, {QStringLiteral("set"), QStringLiteral("org.gnome.system.proxy.https"), QStringLiteral("port"), portText});
        runGsettings(user, {QStringLiteral("set"), QStringLiteral("org.gnome.system.proxy"), QStringLiteral("ignore-hosts"),
                            QStringLiteral("['localhost', '127.0.0.0/8', '::1']")});
        runKde(user, QStringLiteral("ProxyType"), QStringLiteral("1"));
        runKde(user, QStringLiteral("httpProxy"), url);
        runKde(user, QStringLiteral("httpsProxy"), url);
        runKde(user, QStringLiteral("NoProxyFor"), QStringLiteral("localhost,127.0.0.0/8,::1"));
    }
}

void SystemConfig::disableProxy()
{
    writeEnvBlock(0);
    for (const DesktopUser& user : desktopUsers()) {
        runGsettings(user, {QStringLiteral("set"), QStringLiteral("org.gnome.system.proxy"), QStringLiteral("mode"), QStringLiteral("none")});
        runKde(user, QStringLiteral("ProxyType"), QStringLiteral("0"));
    }
}

void SystemConfig::restore(const QJsonObject& snap)
{
    restorePath(kEnvFile, snap.value(QStringLiteral("env")).toObject());

    const QJsonObject gnome = snap.value(QStringLiteral("gnome")).toObject();
    const QJsonObject kde = snap.value(QStringLiteral("kde")).toObject();
    for (const DesktopUser& user : desktopUsers()) {
        const QJsonObject values = gnome.value(user.name).toObject();
        for (auto it = values.begin(); it != values.end(); ++it) {
            const QStringList parts = it.key().split(QLatin1Char(' '));
            if (parts.size() == 2 && !it.value().toString().isEmpty())
                runGsettings(user, {QStringLiteral("set"), parts.at(0), parts.at(1), it.value().toString()});
        }
        const QJsonObject kdeSnap = kde.value(user.name).toObject();
        if (!kdeSnap.isEmpty()) {
            const QString path = user.home + QStringLiteral("/.config/kioslaverc");
            restorePath(path, kdeSnap);
            if (QFileInfo::exists(path))
                (void)::chown(path.toLocal8Bit().constData(), user.uid, user.gid);
        }
    }

    // DNS: remove our drop-in (or put back what was there) and restore resolv.conf.
    const QJsonObject dropin = snap.value(QStringLiteral("dropin")).toObject();
    if (dropin.value(QStringLiteral("kind")).toString() == QLatin1String("file"))
        restorePath(kDropIn, dropin);
    else
        QFile::remove(kDropIn);
    restorePath(kResolvConf, snap.value(QStringLiteral("resolv")).toObject());
    CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("restart"), QStringLiteral("systemd-resolved")});
}

#endif

} // namespace sdns
