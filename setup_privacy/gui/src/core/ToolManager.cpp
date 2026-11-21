#include "ToolManager.h"

#include "CommandRunner.h"
#include "HttpClient.h"
#include "Platform.h"
#include "Translator.h"

#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QSysInfo>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QThread>

#ifdef Q_OS_WIN
#include <QSettings>
#include <windows.h>
#endif

namespace sdns {

namespace {

const QString kServiceName = QStringLiteral("security-dns");
const QString kWgIface = QStringLiteral("security-dns");

[[noreturn]] void fail(ProblemKind kind, const QString& detail, const QVariantMap& params = {})
{
    throw OperationError(makeProblem(kind, detail, params));
}

bool portInUse(int port)
{
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, static_cast<quint16>(port));
    return socket.waitForConnected(600);
}

int findFreePort(int start)
{
    for (int p = start; p <= qMin(start + 200, 65535); ++p) {
        QTcpServer server;
        if (server.listen(QHostAddress::LocalHost, static_cast<quint16>(p)))
            return p;
    }
    return 0;
}

QString osToken()
{
#ifdef Q_OS_WIN
    return QStringLiteral("windows");
#else
    return QStringLiteral("linux");
#endif
}

// Regex for the CPU part of release file names.
QString archPattern(QString* label = nullptr)
{
    const QString cpu = QSysInfo::currentCpuArchitecture();
    if (cpu == QLatin1String("arm64")) {
        if (label) *label = QStringLiteral("arm64");
        return QStringLiteral("arm64|aarch64");
    }
    if (label) *label = QStringLiteral("amd64");
    return QStringLiteral("amd64|x86_64|x64");
}

bool isSidecarFile(const QString& name)
{
    static const QRegularExpression re(QStringLiteral("\\.(sha256|sha512|sig|asc|txt|md5|json|pem|sbom|sh)$"),
                                       QRegularExpression::CaseInsensitiveOption);
    return re.match(name).hasMatch();
}

// Chooses the release file for this OS and CPU. archivesOnly keeps .tar.gz/.zip files.
ReleaseAsset pickAsset(const ReleaseInfo& release, bool archivesOnly, const QString& repoLabel)
{
    QString label;
    const QRegularExpression arch(archPattern(&label), QRegularExpression::CaseInsensitiveOption);
    const QString os = osToken();
    for (const ReleaseAsset& a : release.assets) {
        const QString name = a.name.toLower();
        if (!name.contains(os) || !arch.match(name).hasMatch() || isSidecarFile(name))
            continue;
        const bool archive = name.endsWith(QLatin1String(".tar.gz")) || name.endsWith(QLatin1String(".tgz"))
                             || name.endsWith(QLatin1String(".zip"));
        if (archivesOnly && !archive)
            continue;
        return a;
    }
    fail(ProblemKind::AssetNotFound,
         QStringLiteral("No %1-%2 asset found in %3 release %4").arg(os, label, repoLabel, release.tag));
}

QString findChecksumUrl(const ReleaseInfo& release, QUrl* url)
{
    const QString os = osToken();
    for (const ReleaseAsset& a : release.assets) {
        const QString name = a.name.toLower();
        if (!(name.contains(QLatin1String("sha256")) || name.contains(QLatin1String("checksum"))))
            continue;
        if (name.contains(QLatin1String("windows")) && os != QLatin1String("windows")) continue;
        if (name.contains(QLatin1String("linux")) && os != QLatin1String("linux")) continue;
        if (name.contains(QLatin1String("darwin")) || name.contains(QLatin1String("macos"))) continue;
        *url = a.url;
        return a.name;
    }
    return QString();
}

void checkSha256(const QString& file, const QString& expected, const QString& assetName)
{
    QFile f(file);
    if (!f.open(QIODevice::ReadOnly))
        fail(ProblemKind::Unknown, QStringLiteral("Cannot read %1 to verify its checksum").arg(file));
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(&f);
    if (QString::fromLatin1(hash.result().toHex()).compare(expected, Qt::CaseInsensitive) != 0)
        fail(ProblemKind::ChecksumMismatch, QStringLiteral("SHA-256 mismatch for %1").arg(assetName));
}

// True when the checksum file listed this asset and the file matched. A file that lists many assets
// must name ours; the only exception is a file holding a single hash with no name.
bool verifyChecksum(const QString& file, const QString& assetName, const QString& sumsText)
{
    QString expected;
    const QStringList lines = sumsText.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    const QRegularExpression space(QStringLiteral("\\s+"));
    for (const QString& line : lines) {
        if (line.contains(assetName)) {
            expected = line.trimmed().split(space).value(0);
            break;
        }
    }
    if (expected.isEmpty() && lines.size() == 1)
        expected = lines.first().trimmed().split(space).value(0);
    static const QRegularExpression hex(QStringLiteral("^[0-9a-fA-F]{64}$"));
    if (!hex.match(expected).hasMatch())
        return false;
    checkSha256(file, expected, assetName);
    return true;
}

void writeFile(const QString& path, const QByteArray& data, QFileDevice::Permissions perms = {})
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        fail(ProblemKind::PermissionDenied, QStringLiteral("Permission denied: cannot write %1").arg(path));
    f.write(data);
    f.close();
    if (static_cast<int>(perms) != 0)
        f.setPermissions(perms);
}

QFileDevice::Permissions executablePerms()
{
    return QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner | QFileDevice::ReadGroup
           | QFileDevice::ExeGroup | QFileDevice::ReadOther | QFileDevice::ExeOther;
}

// Quotes one argument for a systemd unit file. systemd treats %, $ and backslash specially,
// so each is escaped; values that reach this point were already checked against an allow-list.
QString systemdQuote(const QString& a)
{
    QString s = a;
    s.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    s.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    s.replace(QLatin1Char('%'), QStringLiteral("%%"));
    s.replace(QLatin1Char('$'), QStringLiteral("$$"));
    return QStringLiteral("\"%1\"").arg(s);
}

// True when the help text lists --name or -name. Both spellings matter: older builds print
// "-addr", newer ones print "--listen-addr".
bool helpHasFlag(const QString& help, const QString& flag)
{
    const QRegularExpression re(QStringLiteral("(?m)(^|[^\\w-])--?%1([^\\w-]|$)").arg(QRegularExpression::escape(flag)));
    return re.match(help).hasMatch();
}

// Letters, digits, space and . _ = : / @ , + - only. No quotes, %, $, ; & or |.
bool safeArgText(const QString& text)
{
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9 ._=:/@,+-]*$"));
    return re.match(text).hasMatch();
}

// Downloads are kept inside the protected data folder, never in a user-writable temp folder, so
// another process cannot swap a file between the checks and the moment it is run with high rights.
QString tempTemplate()
{
    platform::ensureDataDir();
    QDir().mkpath(platform::dataDir() + QStringLiteral("/tmp"));
    return platform::dataDir() + QStringLiteral("/tmp/dl-XXXXXX");
}

#ifdef Q_OS_WIN
// MSI installers run as SYSTEM, so the publisher's Authenticode signature is checked first.
void assertSignedBy(const QString& path, const QString& publisher)
{
    QString p = path;
    p.replace(QLatin1Char('\''), QStringLiteral("''"));
    const CommandResult r = CommandRunner::runPowerShell(
        QStringLiteral("$s = Get-AuthenticodeSignature -LiteralPath '%1'; if ($s.Status -eq 'Valid') { $s.SignerCertificate.Subject } else { 'INVALID:' + $s.Status }").arg(p));
    const QString out = r.out.trimmed();
    if (!r.ok() || out.startsWith(QLatin1String("INVALID")) || !out.contains(publisher, Qt::CaseInsensitive))
        fail(ProblemKind::ChecksumMismatch,
             QStringLiteral("The downloaded file is not signed by %1 (%2). Refusing to install (checksum error).").arg(publisher, out));
}
#endif

#ifdef Q_OS_WIN
QString findProductCode(const QString& namePrefix)
{
    const QStringList roots = {
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")};
    for (const QString& root : roots) {
        QSettings reg(root, QSettings::NativeFormat);
        for (const QString& group : reg.childGroups()) {
            reg.beginGroup(group);
            const QString name = reg.value(QStringLiteral("DisplayName")).toString();
            reg.endGroup();
            if (name.startsWith(namePrefix, Qt::CaseInsensitive))
                return group;
        }
    }
    return QString();
}

void installMsi(const QString& msiPath)
{
    const CommandResult r = CommandRunner::run(QStringLiteral("msiexec.exe"),
        {QStringLiteral("/i"), msiPath, QStringLiteral("/qn"), QStringLiteral("/norestart")}, 600000);
    if (!r.started || r.timedOut || (r.exitCode != 0 && r.exitCode != 3010))
        throw OperationError(analyzer::classify(QStringLiteral("msiexec.exe"), r));
}

void removeMsi(const QString& productCode)
{
    if (productCode.isEmpty())
        return;
    CommandRunner::run(QStringLiteral("msiexec.exe"),
                       {QStringLiteral("/x"), productCode, QStringLiteral("/qn"), QStringLiteral("/norestart")}, 600000);
}
#endif

} // namespace

int ToolManager::freePortNear(int start) { return findFreePort(start); }

ToolManager::ToolManager(const Settings& settings, LogFn log) : m_s(settings), m_log(std::move(log)) {}

void ToolManager::log(const QString& message) const
{
    if (m_log)
        m_log(message);
}

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------
ToolStatus ToolManager::status(Tool tool)
{
    switch (tool) {
    case Tool::SpoofDpi: return spoofStatus();
    case Tool::Warp: return warpStatus();
    case Tool::WireGuard: return wgStatus();
    }
    return {};
}

void ToolManager::perform(Tool tool, ToolAction action)
{
    throwIfCancelled();
    using A = ToolAction;
    switch (tool) {
    case Tool::SpoofDpi:
        switch (action) {
        case A::Install: spoofInstall(); break;
        case A::Start: spoofStart(); break;
        case A::Stop: spoofStop(); break;
        case A::Enable: spoofEnable(); break;
        case A::Disable: spoofDisable(); break;
        case A::Uninstall: spoofUninstall(); break;
        }
        break;
    case Tool::Warp:
        switch (action) {
        case A::Install: warpInstall(); break;
        case A::Start: warpStart(); break;
        case A::Stop: warpStop(); break;
        case A::Enable: warpEnable(); break;
        case A::Disable: warpDisable(); break;
        case A::Uninstall: warpUninstall(); break;
        }
        break;
    case Tool::WireGuard:
        switch (action) {
        case A::Install: wgInstall(); break;
        case A::Start: wgStart(); break;
        case A::Stop: wgStop(); break;
        case A::Enable: wgEnable(); break;
        case A::Disable: wgDisable(); break;
        case A::Uninstall: wgUninstall(); break;
        }
        break;
    }
}

void ToolManager::installPackages(const QStringList& packages)
{
    if (packages.isEmpty())
        return;
    const QString pm = platform::packageManager();
    log(QStringLiteral("Installing packages with %1: %2").arg(pm, packages.join(QLatin1Char(' '))));
    if (pm == QLatin1String("apt")) {
        CommandRunner::run(QStringLiteral("env"), {QStringLiteral("DEBIAN_FRONTEND=noninteractive"),
                           QStringLiteral("apt-get"), QStringLiteral("update"), QStringLiteral("-qq")}, 300000);
        QStringList args = {QStringLiteral("DEBIAN_FRONTEND=noninteractive"), QStringLiteral("apt-get"),
                            QStringLiteral("install"), QStringLiteral("-y"), QStringLiteral("-qq"), QStringLiteral("--no-remove")};
        CommandRunner::runChecked(QStringLiteral("env"), args + packages, 900000);
    } else if (pm == QLatin1String("dnf")) {
        CommandRunner::runChecked(QStringLiteral("dnf"), QStringList{QStringLiteral("install"), QStringLiteral("-y"), QStringLiteral("-q")} + packages, 900000);
    } else if (pm == QLatin1String("pacman")) {
        CommandRunner::runChecked(QStringLiteral("pacman"), QStringList{QStringLiteral("-S"), QStringLiteral("--needed"), QStringLiteral("--noconfirm")} + packages, 900000);
    } else if (pm == QLatin1String("zypper")) {
        CommandRunner::runChecked(QStringLiteral("zypper"), QStringList{QStringLiteral("--non-interactive"), QStringLiteral("install")} + packages, 900000);
    } else {
        fail(ProblemKind::Unknown, QStringLiteral("No supported package manager found. Install manually: %1").arg(packages.join(QLatin1Char(' '))));
    }
}

void ToolManager::removePackages(const QStringList& packages)
{
    const QString pm = platform::packageManager();
    if (pm == QLatin1String("apt"))
        CommandRunner::run(QStringLiteral("env"), QStringList{QStringLiteral("DEBIAN_FRONTEND=noninteractive"), QStringLiteral("apt-get"), QStringLiteral("remove"), QStringLiteral("-y"), QStringLiteral("-qq")} + packages, 600000);
    else if (pm == QLatin1String("dnf"))
        CommandRunner::run(QStringLiteral("dnf"), QStringList{QStringLiteral("remove"), QStringLiteral("-y"), QStringLiteral("-q")} + packages, 600000);
    else if (pm == QLatin1String("pacman"))
        CommandRunner::run(QStringLiteral("pacman"), QStringList{QStringLiteral("-R"), QStringLiteral("--noconfirm")} + packages, 600000);
    else if (pm == QLatin1String("zypper"))
        CommandRunner::run(QStringLiteral("zypper"), QStringList{QStringLiteral("--non-interactive"), QStringLiteral("remove")} + packages, 600000);
}

// =============================================================================
// SpoofDPI
// =============================================================================
QString ToolManager::spoofBin() const
{
    if (!m_s.spoofPath.isEmpty())
        return m_s.spoofPath;
    return platform::binDir() + QStringLiteral("/spoofdpi") + platform::exeSuffix();
}

// The installed build's own --help text, cached until the program changes.
QString ToolManager::spoofHelp()
{
    const QFileInfo info(spoofBin());
    const QString key = info.absoluteFilePath() + QLatin1Char('|') + QString::number(info.lastModified().toSecsSinceEpoch());
    if (key != m_helpKey) {
        m_helpText = CommandRunner::run(spoofBin(), {QStringLiteral("--help")}, 8000).combined();
        m_helpKey = key;
    }
    return m_helpText;
}

// Reads --help to learn how this build takes its address and port:
// listen, config, flags, port, or none (a fixed port 8080).
QString ToolManager::spoofStyle()
{
    if (m_s.spoofArgStyle != QLatin1String("auto"))
        return m_s.spoofArgStyle;
    const QString help = spoofHelp();
    if (helpHasFlag(help, QStringLiteral("listen-addr"))) return QStringLiteral("listen");
    if (helpHasFlag(help, QStringLiteral("config"))) return QStringLiteral("config");
    if (helpHasFlag(help, QStringLiteral("addr")) && helpHasFlag(help, QStringLiteral("port"))) return QStringLiteral("flags");
    if (helpHasFlag(help, QStringLiteral("port"))) return QStringLiteral("port");
    return QStringLiteral("none");
}

int ToolManager::spoofEffectivePort()
{
    return spoofStyle() == QLatin1String("none") ? 8080 : m_s.spoofPort;
}

// SpoofDPI looks up website names itself. Left alone it uses plaintext DNS (UDP to 8.8.8.8 by
// default), which would show every site name to your ISP. This warns when no safe option exists.
void ToolManager::warnIfNoDnsOption()
{
    const QString help = spoofHelp();
    if (!helpHasFlag(help, QStringLiteral("dns-mode")) && !helpHasFlag(help, QStringLiteral("enable-doh")))
        log(QStringLiteral("WARNING: ") + T(QStringLiteral("log.dns_flags_missing")));
}

QStringList ToolManager::spoofArgs(int port)
{
    QStringList args;
    const QString style = spoofStyle();
    const QString help = spoofHelp();

    if (style == QLatin1String("listen")) {
        args << QStringLiteral("--listen-addr") << QStringLiteral("127.0.0.1:%1").arg(port);
    } else if (style == QLatin1String("config")) {
        // The config file lives in the bin folder: readable by the autostart launcher, writable only by administrators.
        const QString cfg = platform::binDir() + QStringLiteral("/spoofdpi.toml");
        QString toml = QStringLiteral("[app]\nlisten-addr = \"127.0.0.1:%1\"\n").arg(port);
        if (helpHasFlag(help, QStringLiteral("dns-mode")))
            toml += QStringLiteral("\n[dns]\nmode = \"system\"\n");
        writeFile(cfg, toml.toUtf8());
        args << QStringLiteral("--config") << cfg;
    } else if (style == QLatin1String("flags")) {
        args << QStringLiteral("--addr") << QStringLiteral("127.0.0.1") << QStringLiteral("--port") << QString::number(port);
    } else if (style == QLatin1String("port")) {
        args << QStringLiteral("--port") << QString::number(port);
    }

    // DNS: make the proxy resolve names through the encrypted system resolver.
    if (style != QLatin1String("config")) {
        if (helpHasFlag(help, QStringLiteral("dns-mode")))
            args << QStringLiteral("--dns-mode") << QStringLiteral("system");
        else if (helpHasFlag(help, QStringLiteral("enable-doh")))
            args << QStringLiteral("--enable-doh") << QStringLiteral("--dns-addr") << QStringLiteral("1.1.1.1");
    }
    // No terminal exists for a background service, so switch the text interface off where the build has one.
    if (helpHasFlag(help, QStringLiteral("no-tui")))
        args << QStringLiteral("--no-tui=true");
    else if (helpHasFlag(help, QStringLiteral("silent")))
        args << QStringLiteral("--silent");
    for (const QString& name : {QStringLiteral("system-proxy"), QStringLiteral("set-system-proxy")}) {
        if (helpHasFlag(help, name))
            args << QStringLiteral("--%1=false").arg(name);
    }
    if (!m_s.spoofExtraArgs.trimmed().isEmpty()) {
        if (!safeArgText(m_s.spoofExtraArgs))
            fail(ProblemKind::Unknown, QStringLiteral("The SpoofDPI extra arguments contain characters that are not allowed."));
        args += QProcess::splitCommand(m_s.spoofExtraArgs);
    }
    return args;
}

// Verifies a download with the release checksum file, or else with GitHub's published digest.
void ToolManager::verifyDownload(HttpClient& http, const ReleaseInfo& release, const ReleaseAsset& asset, const QString& file)
{
    QUrl sumsUrl;
    if (!findChecksumUrl(release, &sumsUrl).isEmpty()) {
        if (verifyChecksum(file, asset.name, QString::fromUtf8(http.get(sumsUrl)))) {
            log(QStringLiteral("SHA-256 checksum verified."));
            return;
        }
    }
    static const QRegularExpression digestRe(QStringLiteral("^sha256:([0-9a-fA-F]{64})$"));
    const QRegularExpressionMatch m = digestRe.match(asset.digest);
    if (m.hasMatch()) {
        checkSha256(file, m.captured(1), asset.name);
        log(QStringLiteral("SHA-256 digest verified."));
        return;
    }
    log(QStringLiteral("No checksum or digest is published for %1; integrity was not verified.").arg(asset.name));
}

ToolStatus ToolManager::spoofStatus()
{
    ToolStatus s;
    s.installed = QFileInfo(spoofBin()).isFile();
    s.version = StateStore::str(QStringLiteral("spoofdpiTag"));
#ifdef Q_OS_WIN
    const QString exe = QFileInfo(spoofBin()).fileName();
    s.running = CommandRunner::run(QStringLiteral("tasklist"),
                    {QStringLiteral("/FI"), QStringLiteral("IMAGENAME eq %1").arg(exe), QStringLiteral("/NH")}, 8000)
                    .out.contains(exe, Qt::CaseInsensitive);
    s.enabled = QFileInfo::exists(platform::startupFolder() + QStringLiteral("/security-dns.vbs"));
#else
    s.running = CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("is-active"), QStringLiteral("--quiet"), kServiceName}, 8000).ok();
    s.enabled = CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("is-enabled"), QStringLiteral("--quiet"), kServiceName}, 8000).ok();
#endif
    return s;
}

void ToolManager::spoofInstall()
{
    if (!m_s.spoofPath.isEmpty() && QFileInfo(m_s.spoofPath).isFile()) {
        log(QStringLiteral("Using your own SpoofDPI program: %1").arg(m_s.spoofPath));
        return;
    }
    HttpClient http(m_s.networkTimeoutSec, m_s.githubToken);
    const ReleaseInfo release = http.latestRelease(QStringLiteral("xvzc/SpoofDPI"));
    if (release.tag == StateStore::str(QStringLiteral("spoofdpiTag")) && QFileInfo(spoofBin()).isFile()) {
        log(QStringLiteral("SpoofDPI is up to date (%1).").arg(release.tag));
        return;
    }
    const ReleaseAsset asset = pickAsset(release, true, QStringLiteral("SpoofDPI"));

    QTemporaryDir tmp(tempTemplate());
    if (!tmp.isValid())
        fail(ProblemKind::PermissionDenied, QStringLiteral("Permission denied: cannot create a temporary folder"));
    const QString archive = tmp.path() + QLatin1Char('/') + asset.name;
    log(QStringLiteral("Downloading SpoofDPI %1 (%2)").arg(release.tag, asset.name));
    http.download(asset.url, archive);

    verifyDownload(http, release, asset, archive);

    const QString extractDir = tmp.path() + QStringLiteral("/extract");
    QDir().mkpath(extractDir);
    CommandRunner::runChecked(QStringLiteral("tar"), {QStringLiteral("-xf"), archive, QStringLiteral("-C"), extractDir}, 180000);

    QString found;
    QDirIterator it(extractDir, {QStringLiteral("spoofdpi"), QStringLiteral("spoof-dpi"), QStringLiteral("spoofdpi.exe")},
                    QDir::Files, QDirIterator::Subdirectories);
    if (it.hasNext())
        found = it.next();
    if (found.isEmpty())
        fail(ProblemKind::AssetNotFound, QStringLiteral("No spoofdpi program asset found inside %1").arg(asset.name));

    QDir().mkpath(platform::binDir());
    QFile::remove(spoofBin());
    if (!QFile::copy(found, spoofBin()))
        fail(ProblemKind::PermissionDenied, QStringLiteral("Permission denied: cannot write %1").arg(spoofBin()));
    QFile(spoofBin()).setPermissions(executablePerms());
    StateStore::set(QStringLiteral("spoofdpiTag"), release.tag);
    log(QStringLiteral("Installed SpoofDPI %1").arg(release.tag));
}

void ToolManager::spoofStop()
{
#ifdef Q_OS_WIN
    CommandRunner::run(QStringLiteral("taskkill"), {QStringLiteral("/F"), QStringLiteral("/IM"), QFileInfo(spoofBin()).fileName()}, 10000);
#else
    CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("stop"), kServiceName}, 15000);
#endif
}

void ToolManager::spoofStart()
{
    if (!QFileInfo(spoofBin()).isFile())
        fail(ProblemKind::MissingTool, QStringLiteral("spoofdpi: command not found (not installed)"),
             {{QStringLiteral("tool"), QStringLiteral("spoofdpi")}});

    warnIfNoDnsOption();
    spoofStop();
    const int port = spoofEffectivePort();
    if (portInUse(port))
        fail(ProblemKind::PortInUse, QStringLiteral("Port %1 is already in use by another application.").arg(port),
             {{QStringLiteral("port"), port}});

    const QStringList args = spoofArgs(port);

    // Test run: a healthy SpoofDPI keeps running until the timeout stops it.
    const CommandResult test = CommandRunner::run(spoofBin(), args, 4000);
    if (!test.timedOut) {
        Problem p = analyzer::classify(spoofBin(), test);
        throw OperationError(p);
    }
    log(QStringLiteral("SpoofDPI started correctly in a test run."));

    QString logs;
#ifdef Q_OS_WIN
    const QString outLog = platform::dataDir() + QStringLiteral("/logs/spoofdpi.out.log");
    const QString errLog = platform::dataDir() + QStringLiteral("/logs/spoofdpi.err.log");
    QDir().mkpath(platform::dataDir() + QStringLiteral("/logs"));
    QProcess proc;
    proc.setProgram(spoofBin());
    proc.setArguments(args);
    proc.setStandardOutputFile(outLog);
    proc.setStandardErrorFile(errLog);
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* a) {
        a->flags |= CREATE_NO_WINDOW;
    });
    qint64 pid = 0;
    if (!proc.startDetached(&pid))
        fail(ProblemKind::Unknown, QStringLiteral("Could not start SpoofDPI: %1").arg(proc.errorString()));
#else
    QStringList quoted;
    for (const QString& a : args)
        quoted << systemdQuote(a);
    const QString unit = QStringLiteral(
        "[Unit]\nDescription=Security DNS - SpoofDPI local DPI-bypass proxy\nAfter=network-online.target systemd-resolved.service\n"
        "Wants=network-online.target\n\n[Service]\nType=simple\nExecStart=%1 %2\nRestart=on-failure\nRestartSec=5\n"
        "DynamicUser=yes\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n\n"
        "[Install]\nWantedBy=multi-user.target\n").arg(systemdQuote(spoofBin()), quoted.join(QLatin1Char(' ')));
    writeFile(QStringLiteral("/etc/systemd/system/%1.service").arg(kServiceName), unit.toUtf8(),
              QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    CommandRunner::runChecked(QStringLiteral("systemctl"), {QStringLiteral("daemon-reload")});
    CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("restart"), kServiceName}, 30000);
#endif

    // Wait up to about 15 seconds for the port to open.
    interruptibleSleep(2000);
    for (int i = 0; i < 20; ++i) {
        if (portInUse(port)) {
            log(QStringLiteral("SpoofDPI is listening on 127.0.0.1:%1").arg(port));
            return;
        }
        interruptibleSleep(750);
    }
#ifdef Q_OS_WIN
    for (const QString& file : {errLog, outLog}) {
        QFile f(file);
        if (f.open(QIODevice::ReadOnly))
            logs += QString::fromUtf8(f.readAll());
    }
#else
    logs = CommandRunner::run(QStringLiteral("journalctl"),
               {QStringLiteral("-u"), kServiceName, QStringLiteral("-n"), QStringLiteral("40"), QStringLiteral("--no-pager")}, 15000).combined();
#endif
    Problem p = analyzer::classifyText(QStringLiteral("SpoofDPI did not start and listen on its port.\n") + logs);
    throw OperationError(p);
}

void ToolManager::spoofEnable()
{
    if (!QFileInfo(spoofBin()).isFile())
        fail(ProblemKind::MissingTool, QStringLiteral("spoofdpi: command not found (not installed)"),
             {{QStringLiteral("tool"), QStringLiteral("spoofdpi")}});
#ifdef Q_OS_WIN
    const int port = spoofEffectivePort();
    QStringList quoted;
    for (const QString& a : spoofArgs(port))
        quoted << a;
    QString argLine = quoted.join(QLatin1Char(' '));
    argLine.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    const QString vbs = QStringLiteral("' Security DNS - hidden launcher for SpoofDPI.\nSet shell = CreateObject(\"WScript.Shell\")\n"
                                       "shell.Run \"\"\"%1\"\" %2\", 0, False\n").arg(spoofBin(), argLine);
    writeFile(platform::startupFolder() + QStringLiteral("/security-dns.vbs"), vbs.toLatin1());
#else
    if (!QFileInfo::exists(QStringLiteral("/etc/systemd/system/%1.service").arg(kServiceName)))
        log(QStringLiteral("The service file is created the first time SpoofDPI starts."));
    CommandRunner::runChecked(QStringLiteral("systemctl"), {QStringLiteral("enable"), kServiceName});
#endif
}

void ToolManager::spoofDisable()
{
#ifdef Q_OS_WIN
    QFile::remove(platform::startupFolder() + QStringLiteral("/security-dns.vbs"));
#else
    CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("disable"), kServiceName}, 15000);
#endif
}

void ToolManager::spoofUninstall()
{
    spoofStop();
    spoofDisable();
#ifndef Q_OS_WIN
    QFile::remove(QStringLiteral("/etc/systemd/system/%1.service").arg(kServiceName));
    CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("daemon-reload")});
#endif
    QFile::remove(platform::dataDir() + QStringLiteral("/spoofdpi.toml"));
    if (!StateStore::str(QStringLiteral("spoofdpiTag")).isEmpty()) {
        QFile::remove(platform::binDir() + QStringLiteral("/spoofdpi") + platform::exeSuffix());
        StateStore::remove(QStringLiteral("spoofdpiTag"));
        log(QStringLiteral("SpoofDPI program removed."));
    } else {
        log(QStringLiteral("SpoofDPI was not installed by this app; the program was left in place."));
    }
}

// =============================================================================
// Cloudflare WARP
// =============================================================================
QString ToolManager::warpCli() const
{
    if (!m_s.warpCliPath.isEmpty())
        return m_s.warpCliPath;
#ifdef Q_OS_WIN
    return qEnvironmentVariable("ProgramFiles", QStringLiteral("C:/Program Files"))
           + QStringLiteral("/Cloudflare/Cloudflare WARP/warp-cli.exe");
#else
    const QString p = platform::findTool(QStringLiteral("warp-cli"));
    return p.isEmpty() ? QStringLiteral("warp-cli") : p;
#endif
}

ToolStatus ToolManager::warpStatus()
{
    ToolStatus s;
#ifdef Q_OS_WIN
    s.installed = QFileInfo(warpCli()).isFile();
#else
    s.installed = !platform::findTool(QStringLiteral("warp-cli")).isEmpty() || QFileInfo(m_s.warpCliPath).isFile();
#endif
    if (!s.installed)
        return s;
    const CommandResult r = CommandRunner::run(warpCli(), {QStringLiteral("--accept-tos"), QStringLiteral("status")}, 10000);
    s.running = QRegularExpression(QStringLiteral("Status update:\\s*Connected"), QRegularExpression::CaseInsensitiveOption)
                    .match(r.combined()).hasMatch();
#ifdef Q_OS_WIN
    s.enabled = CommandRunner::run(QStringLiteral("sc"), {QStringLiteral("qc"), QStringLiteral("CloudflareWARP")}, 8000)
                    .out.contains(QStringLiteral("AUTO_START"));
#else
    s.enabled = CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("is-enabled"), QStringLiteral("--quiet"), QStringLiteral("warp-svc")}, 8000).ok();
#endif
    return s;
}

void ToolManager::warpInstall()
{
    if (warpStatus().installed) {
        log(QStringLiteral("Cloudflare WARP client is already installed; it will be left in place on uninstall."));
        return;
    }
    HttpClient http(m_s.networkTimeoutSec, m_s.githubToken);
#ifdef Q_OS_WIN
    QTemporaryDir tmp(tempTemplate());
    const QString msi = tmp.path() + QStringLiteral("/warp.msi");
    http.download(QUrl(QStringLiteral("https://downloads.cloudflareclient.com/v1/download/windows/ga")), msi);
    assertSignedBy(msi, QStringLiteral("Cloudflare"));
    StateStore::set(QStringLiteral("warpMsiAdded"), true);
    installMsi(msi);
    StateStore::set(QStringLiteral("warpProductCode"), findProductCode(QStringLiteral("Cloudflare WARP")));
#else
    const QString pm = platform::packageManager();
    if (pm == QLatin1String("apt")) {
        if (platform::findTool(QStringLiteral("gpg")).isEmpty())
            installPackages({QStringLiteral("gnupg")});
        QString codename;
        QFile osRelease(QStringLiteral("/etc/os-release"));
        if (osRelease.open(QIODevice::ReadOnly | QIODevice::Text)) {
            const QRegularExpressionMatch m = QRegularExpression(QStringLiteral("(?m)^VERSION_CODENAME=(\\S+)$"))
                                                  .match(QString::fromUtf8(osRelease.readAll()));
            codename = m.captured(1);
        }
        if (codename.isEmpty())
            fail(ProblemKind::AssetNotFound, QStringLiteral("No release codename found for the Cloudflare WARP repository"));
        const QString keyring = QStringLiteral("/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg");
        const QString list = QStringLiteral("/etc/apt/sources.list.d/cloudflare-client.list");
        if (!QFileInfo::exists(keyring)) StateStore::set(QStringLiteral("warpKeyAdded"), true);
        if (!QFileInfo::exists(list)) StateStore::set(QStringLiteral("warpRepoAdded"), true);
        const QByteArray key = http.get(QUrl(QStringLiteral("https://pkg.cloudflareclient.com/pubkey.gpg")));
        CommandRunner::runChecked(QStringLiteral("gpg"), {QStringLiteral("--yes"), QStringLiteral("--dearmor"), QStringLiteral("--output"), keyring}, 30000, key);
        writeFile(list, QStringLiteral("deb [signed-by=%1] https://pkg.cloudflareclient.com/ %2 main\n").arg(keyring, codename).toUtf8());
        CommandRunner::runChecked(QStringLiteral("env"), {QStringLiteral("DEBIAN_FRONTEND=noninteractive"), QStringLiteral("apt-get"), QStringLiteral("update"), QStringLiteral("-qq")}, 300000);
        StateStore::set(QStringLiteral("warpPkgAdded"), true);
        installPackages({QStringLiteral("cloudflare-warp")});
    } else if (pm == QLatin1String("dnf")) {
        const QString repo = QStringLiteral("/etc/yum.repos.d/cloudflare-warp.repo");
        if (!QFileInfo::exists(repo)) StateStore::set(QStringLiteral("warpRepoAdded"), true);
        http.download(QUrl(QStringLiteral("https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo")), repo);
        StateStore::set(QStringLiteral("warpPkgAdded"), true);
        installPackages({QStringLiteral("cloudflare-warp")});
    } else {
        fail(ProblemKind::AssetNotFound, QStringLiteral("No WARP package asset found for this system (apt or dnf is required)"));
    }
#endif
    log(QStringLiteral("Cloudflare WARP client installed."));
}

void ToolManager::warpStart()
{
    if (!warpStatus().installed)
        fail(ProblemKind::MissingTool, QStringLiteral("warp-cli: command not found (not installed)"),
             {{QStringLiteral("tool"), QStringLiteral("warp-cli")}});
    if (wgStatus().running)
        fail(ProblemKind::ToolConflict, QStringLiteral("CONFLICT:wireguard - WireGuard is running; WARP cannot start at the same time."),
             {{QStringLiteral("other"), QStringLiteral("wireguard")}});

#ifndef Q_OS_WIN
    CommandRunner::runChecked(QStringLiteral("systemctl"), {QStringLiteral("start"), QStringLiteral("warp-svc")});
    interruptibleSleep(3000);
#endif
    const QStringList tos = {QStringLiteral("--accept-tos")};
    if (!CommandRunner::run(warpCli(), tos + QStringList{QStringLiteral("registration"), QStringLiteral("show")}, 15000).ok()) {
        // Newer clients use "registration new", older ones "register". A failure here is not fatal:
        // "connect" reports the real problem if the client is still unregistered.
        CommandResult reg = CommandRunner::run(warpCli(), tos + QStringList{QStringLiteral("registration"), QStringLiteral("new")}, 60000);
        if (!reg.ok())
            reg = CommandRunner::run(warpCli(), tos + QStringList{QStringLiteral("register")}, 60000);
        if (reg.ok())
            StateStore::set(QStringLiteral("warpRegisteredByUs"), true);
        else
            log(QStringLiteral("WARP registration did not complete: %1").arg(reg.combined()));
    }
    CommandRunner::run(warpCli(), tos + QStringList{QStringLiteral("connect")}, 20000);
    for (int i = 0; i < 20; ++i) {
        if (warpStatus().running) {
            log(QStringLiteral("Cloudflare WARP is connected."));
            return;
        }
        interruptibleSleep(1000);
    }
    fail(ProblemKind::NetworkTimeout, QStringLiteral("WARP did not report Connected (connection timed out). Check: warp-cli status"));
}

void ToolManager::warpStop()
{
    if (warpStatus().installed)
        CommandRunner::run(warpCli(), {QStringLiteral("--accept-tos"), QStringLiteral("disconnect")}, 20000);
}

void ToolManager::warpEnable()
{
    if (!warpStatus().installed)
        fail(ProblemKind::MissingTool, QStringLiteral("warp-cli: command not found (not installed)"),
             {{QStringLiteral("tool"), QStringLiteral("warp-cli")}});
#ifdef Q_OS_WIN
    CommandRunner::runChecked(QStringLiteral("sc"), {QStringLiteral("config"), QStringLiteral("CloudflareWARP"), QStringLiteral("start="), QStringLiteral("auto")});
#else
    CommandRunner::runChecked(QStringLiteral("systemctl"), {QStringLiteral("enable"), QStringLiteral("warp-svc")});
#endif
}

void ToolManager::warpDisable()
{
#ifdef Q_OS_WIN
    CommandRunner::run(QStringLiteral("sc"), {QStringLiteral("config"), QStringLiteral("CloudflareWARP"), QStringLiteral("start="), QStringLiteral("demand")});
#else
    CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("disable"), QStringLiteral("warp-svc")}, 15000);
#endif
}

void ToolManager::warpUninstall()
{
    warpStop();
    if (StateStore::flag(QStringLiteral("warpRegisteredByUs"))) {
        const CommandResult removed = CommandRunner::run(warpCli(), {QStringLiteral("--accept-tos"), QStringLiteral("registration"), QStringLiteral("delete")}, 30000);
        if (!removed.ok())
            CommandRunner::run(warpCli(), {QStringLiteral("--accept-tos"), QStringLiteral("delete")}, 30000);   // older clients
        StateStore::remove(QStringLiteral("warpRegisteredByUs"));
    }
#ifdef Q_OS_WIN
    if (StateStore::flag(QStringLiteral("warpMsiAdded"))) {
        removeMsi(StateStore::str(QStringLiteral("warpProductCode")));
        StateStore::remove(QStringLiteral("warpMsiAdded"));
        StateStore::remove(QStringLiteral("warpProductCode"));
    } else {
        log(QStringLiteral("WARP was not installed by this app; the client was left in place."));
    }
#else
    if (StateStore::flag(QStringLiteral("warpPkgAdded"))) {
        CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("disable"), QStringLiteral("--now"), QStringLiteral("warp-svc")}, 30000);
        removePackages({QStringLiteral("cloudflare-warp")});
        StateStore::remove(QStringLiteral("warpPkgAdded"));
    } else {
        log(QStringLiteral("WARP was not installed by this app; the client was left in place."));
    }
    if (StateStore::flag(QStringLiteral("warpRepoAdded"))) {
        QFile::remove(QStringLiteral("/etc/apt/sources.list.d/cloudflare-client.list"));
        QFile::remove(QStringLiteral("/etc/yum.repos.d/cloudflare-warp.repo"));
        StateStore::remove(QStringLiteral("warpRepoAdded"));
    }
    if (StateStore::flag(QStringLiteral("warpKeyAdded"))) {
        QFile::remove(QStringLiteral("/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"));
        StateStore::remove(QStringLiteral("warpKeyAdded"));
    }
#endif
}

// =============================================================================
// WireGuard with a WARP profile made by wgcf
// =============================================================================
QString ToolManager::wgConfPath() const
{
#ifdef Q_OS_WIN
    return platform::dataDir() + QStringLiteral("/security-dns.conf");
#else
    return QStringLiteral("/etc/wireguard/security-dns.conf");
#endif
}

QString ToolManager::wgcfBin() const
{
    if (!m_s.wgcfPath.isEmpty())
        return m_s.wgcfPath;
    return platform::binDir() + QStringLiteral("/wgcf") + platform::exeSuffix();
}

QString ToolManager::wgQuick() const
{
    if (!m_s.wgQuickPath.isEmpty())
        return m_s.wgQuickPath;
    const QString p = platform::findTool(QStringLiteral("wg-quick"));
    return p.isEmpty() ? QStringLiteral("wg-quick") : p;
}

QString ToolManager::wireguardExe() const
{
    return qEnvironmentVariable("ProgramFiles", QStringLiteral("C:/Program Files")) + QStringLiteral("/WireGuard/wireguard.exe");
}

ToolStatus ToolManager::wgStatus()
{
    ToolStatus s;
#ifdef Q_OS_WIN
    s.installed = QFileInfo(wireguardExe()).isFile() && QFileInfo(wgConfPath()).isFile();
    const QString service = QStringLiteral("WireGuardTunnel$") + kWgIface;
    s.running = CommandRunner::run(QStringLiteral("sc"), {QStringLiteral("query"), service}, 8000).out.contains(QStringLiteral("RUNNING"));
    s.enabled = CommandRunner::run(QStringLiteral("sc"), {QStringLiteral("qc"), service}, 8000).out.contains(QStringLiteral("AUTO_START"));
#else
    s.installed = (!platform::findTool(QStringLiteral("wg-quick")).isEmpty() || QFileInfo(m_s.wgQuickPath).isFile())
                  && QFileInfo(wgConfPath()).isFile();
    s.running = !platform::findTool(QStringLiteral("wg")).isEmpty()
                && CommandRunner::run(QStringLiteral("wg"), {QStringLiteral("show"), kWgIface}, 8000).ok();
    s.enabled = CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("is-enabled"), QStringLiteral("--quiet"),
                                    QStringLiteral("wg-quick@") + kWgIface}, 8000).ok();
#endif
    s.version = StateStore::str(QStringLiteral("wgcfTag"));
    return s;
}

void ToolManager::wgInstall()
{
    HttpClient http(m_s.networkTimeoutSec, m_s.githubToken);

#ifdef Q_OS_WIN
    if (!QFileInfo(wireguardExe()).isFile()) {
        const ReleaseInfo wg = http.latestRelease(QStringLiteral("WireGuard/wireguard-windows"));
        ReleaseAsset msiAsset;
        const QString archToken = QSysInfo::currentCpuArchitecture() == QLatin1String("arm64") ? QStringLiteral("arm64") : QStringLiteral("amd64");
        for (const ReleaseAsset& a : wg.assets) {
            if (a.name.startsWith(QStringLiteral("wireguard-%1-").arg(archToken)) && a.name.endsWith(QLatin1String(".msi"))) { msiAsset = a; break; }
        }
        if (msiAsset.name.isEmpty())
            fail(ProblemKind::AssetNotFound, QStringLiteral("No WireGuard MSI asset found in release %1").arg(wg.tag));
        QTemporaryDir tmp(tempTemplate());
        const QString msi = tmp.path() + QLatin1Char('/') + msiAsset.name;
        http.download(msiAsset.url, msi);
        verifyDownload(http, wg, msiAsset, msi);
        assertSignedBy(msi, QStringLiteral("WireGuard"));
        StateStore::set(QStringLiteral("wgClientAdded"), true);
        installMsi(msi);
        StateStore::set(QStringLiteral("wgProductCode"), findProductCode(QStringLiteral("WireGuard")));
    }
#else
    if (platform::findTool(QStringLiteral("wg-quick")).isEmpty() && !QFileInfo(m_s.wgQuickPath).isFile()) {
        StateStore::set(QStringLiteral("wgToolsAdded"), true);
        installPackages({QStringLiteral("wireguard-tools")});
    }
#endif

    if (m_s.wgcfPath.isEmpty()) {
        const ReleaseInfo release = http.latestRelease(QStringLiteral("ViRb3/wgcf"));
        if (!(release.tag == StateStore::str(QStringLiteral("wgcfTag")) && QFileInfo(wgcfBin()).isFile())) {
            ReleaseAsset asset;
            QString label;
            const QRegularExpression arch(archPattern(&label), QRegularExpression::CaseInsensitiveOption);
            for (const ReleaseAsset& a : release.assets) {
                const QString name = a.name.toLower();
                if (name.contains(osToken()) && arch.match(name).hasMatch() && !isSidecarFile(name)) { asset = a; break; }
            }
            if (asset.name.isEmpty())
                fail(ProblemKind::AssetNotFound, QStringLiteral("No %1-%2 wgcf asset found in release %3").arg(osToken(), label, release.tag));
            if (!QFileInfo(wgcfBin()).isFile())
                StateStore::set(QStringLiteral("wgcfBinAdded"), true);
            QDir().mkpath(platform::binDir());
            QTemporaryDir tmp(tempTemplate());
            const QString download = tmp.path() + QLatin1Char('/') + asset.name;
            http.download(asset.url, download);
            verifyDownload(http, release, asset, download);
            QFile::remove(wgcfBin());
            if (!QFile::copy(download, wgcfBin()))
                fail(ProblemKind::PermissionDenied, QStringLiteral("Permission denied: cannot write %1").arg(wgcfBin()));
            QFile(wgcfBin()).setPermissions(executablePerms());
            StateStore::set(QStringLiteral("wgcfTag"), release.tag);
            log(QStringLiteral("Installed wgcf %1").arg(release.tag));
        }
    }

    const QString workDir = platform::dataDir() + QStringLiteral("/wgcf");
    QDir().mkpath(workDir);
    QFile(workDir).setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    if (!QFileInfo::exists(workDir + QStringLiteral("/wgcf-account.toml")))
        CommandRunner::runChecked(wgcfBin(), {QStringLiteral("register"), QStringLiteral("--accept-tos")}, 120000, {}, workDir);
    if (!QFileInfo::exists(workDir + QStringLiteral("/wgcf-profile.conf")))
        CommandRunner::runChecked(wgcfBin(), {QStringLiteral("generate")}, 120000, {}, workDir);
    wgWriteConf();
    log(QStringLiteral("WireGuard profile ready at %1").arg(wgConfPath()));
}

// Builds the active profile from the wgcf profile plus your settings.
void ToolManager::wgWriteConf()
{
    QFile source(platform::dataDir() + QStringLiteral("/wgcf/wgcf-profile.conf"));
    if (!source.open(QIODevice::ReadOnly | QIODevice::Text))
        fail(ProblemKind::AssetNotFound, QStringLiteral("No WireGuard profile asset found: %1").arg(source.fileName()));
    const QStringList lines = QString::fromUtf8(source.readAll()).split(QLatin1Char('\n'));

    const QRegularExpression dnsLine(QStringLiteral("^\\s*DNS\\s*="));
    const QRegularExpression endpointLine(QStringLiteral("^\\s*Endpoint\\s*="));
    static const QRegularExpression endpointValue(QStringLiteral("^[\\[\\]A-Za-z0-9._:-]+:\\d{1,5}$"));
    if (!m_s.wgEndpoint.trimmed().isEmpty() && !endpointValue.match(m_s.wgEndpoint.trimmed()).hasMatch())
        fail(ProblemKind::Unknown, QStringLiteral("The WireGuard endpoint in the settings is not valid."));
    QStringList out;
    // wg-quick runs PreUp/PostUp/PreDown/PostDown lines as root. The profile comes from Cloudflare's API
    // through wgcf and never needs them, so they are removed rather than trusted.
    static const QRegularExpression scriptLine(QStringLiteral("^\\s*(PreUp|PostUp|PreDown|PostDown|SaveConfig)\\s*="),
                                               QRegularExpression::CaseInsensitiveOption);
    for (const QString& line : lines) {
        if (scriptLine.match(line).hasMatch())
            continue;
#ifndef Q_OS_WIN
        if (m_s.wgStripDns && dnsLine.match(line).hasMatch())
            continue; // the app handles DNS itself, so wg-quick does not need resolvconf
#endif
        if (!m_s.wgEndpoint.trimmed().isEmpty() && endpointLine.match(line).hasMatch())
            out << QStringLiteral("Endpoint = %1").arg(m_s.wgEndpoint.trimmed());
        else
            out << line;
    }
    writeFile(wgConfPath(), out.join(QLatin1Char('\n')).toUtf8(), QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    StateStore::set(QStringLiteral("wgConfAdded"), true);
}

void ToolManager::wgStart()
{
    if (!wgStatus().installed)
        fail(ProblemKind::MissingTool, QStringLiteral("wg-quick: command not found (WireGuard is not installed)"),
             {{QStringLiteral("tool"), QStringLiteral("wg-quick")}});
    if (warpStatus().running)
        fail(ProblemKind::ToolConflict, QStringLiteral("CONFLICT:warp - WARP is connected; WireGuard cannot start at the same time."),
             {{QStringLiteral("other"), QStringLiteral("warp")}});
    if (wgStatus().running)
        wgStop();
    wgWriteConf();
#ifdef Q_OS_WIN
    CommandRunner::runChecked(wireguardExe(), {QStringLiteral("/installtunnelservice"), wgConfPath()}, 60000);
    for (int i = 0; i < 15; ++i) {
        if (wgStatus().running) { log(QStringLiteral("WireGuard tunnel started.")); return; }
        interruptibleSleep(1000);
    }
    fail(ProblemKind::NetworkTimeout, QStringLiteral("WireGuard tunnel did not start (connection timed out)."));
#else
    CommandRunner::runChecked(wgQuick(), {QStringLiteral("up"), kWgIface}, 60000);
    log(QStringLiteral("WireGuard tunnel is up."));
#endif
}

void ToolManager::wgStop()
{
#ifdef Q_OS_WIN
    if (QFileInfo(wireguardExe()).isFile())
        CommandRunner::run(wireguardExe(), {QStringLiteral("/uninstalltunnelservice"), kWgIface}, 30000);
#else
    if (wgStatus().running)
        CommandRunner::run(wgQuick(), {QStringLiteral("down"), kWgIface}, 30000);
#endif
}

void ToolManager::wgEnable()
{
    if (!wgStatus().installed)
        fail(ProblemKind::MissingTool, QStringLiteral("wg-quick: command not found (not installed)"),
             {{QStringLiteral("tool"), QStringLiteral("wg-quick")}});
#ifdef Q_OS_WIN
    CommandRunner::runChecked(QStringLiteral("sc"), {QStringLiteral("config"), QStringLiteral("WireGuardTunnel$") + kWgIface, QStringLiteral("start="), QStringLiteral("auto")});
#else
    CommandRunner::runChecked(QStringLiteral("systemctl"), {QStringLiteral("enable"), QStringLiteral("wg-quick@") + kWgIface});
#endif
}

void ToolManager::wgDisable()
{
#ifdef Q_OS_WIN
    CommandRunner::run(QStringLiteral("sc"), {QStringLiteral("config"), QStringLiteral("WireGuardTunnel$") + kWgIface, QStringLiteral("start="), QStringLiteral("demand")});
#else
    CommandRunner::run(QStringLiteral("systemctl"), {QStringLiteral("disable"), QStringLiteral("wg-quick@") + kWgIface}, 15000);
#endif
}

void ToolManager::wgUninstall()
{
    wgStop();
    wgDisable();
    QFile::remove(wgConfPath());
    QDir(platform::dataDir() + QStringLiteral("/wgcf")).removeRecursively();
    StateStore::remove(QStringLiteral("wgConfAdded"));
#ifdef Q_OS_WIN
    if (StateStore::flag(QStringLiteral("wgClientAdded"))) {
        removeMsi(StateStore::str(QStringLiteral("wgProductCode")));
        StateStore::remove(QStringLiteral("wgClientAdded"));
        StateStore::remove(QStringLiteral("wgProductCode"));
    }
#else
    if (StateStore::flag(QStringLiteral("wgToolsAdded"))) {
        removePackages({QStringLiteral("wireguard-tools")});
        StateStore::remove(QStringLiteral("wgToolsAdded"));
    }
#endif
    if (StateStore::flag(QStringLiteral("wgcfBinAdded"))) {
        QFile::remove(platform::binDir() + QStringLiteral("/wgcf") + platform::exeSuffix());
        StateStore::remove(QStringLiteral("wgcfBinAdded"));
        StateStore::remove(QStringLiteral("wgcfTag"));
    }
}

} // namespace sdns
