#include "Platform.h"

#include <QCoreApplication>
#include <QDir>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QStandardPaths>

#ifdef Q_OS_WIN
#include <windows.h>
#include <shellapi.h>
#else
#include <unistd.h>
#endif

namespace sdns::platform {

bool isElevated()
{
#ifdef Q_OS_WIN
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
#else
    return ::geteuid() == 0;
#endif
}

bool relaunchElevated()
{
    const QString exe = QCoreApplication::applicationFilePath();
#ifdef Q_OS_WIN
    const std::wstring path = exe.toStdWString();
    const HINSTANCE result = ShellExecuteW(nullptr, L"runas", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<quintptr>(result) > 32;
#else
    // pkexec starts the program with a clean environment, so pass the display
    // variables the elevated GUI needs to connect to your desktop.
    QStringList args;
    args << QStringLiteral("env");
    const QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QStringList names = {QStringLiteral("DISPLAY"), QStringLiteral("XAUTHORITY"),
                               QStringLiteral("WAYLAND_DISPLAY"), QStringLiteral("XDG_RUNTIME_DIR"),
                               QStringLiteral("XDG_SESSION_TYPE"), QStringLiteral("QT_QPA_PLATFORM")};
    // Only plain values are passed on to the process that will run with administrator rights.
    static const QRegularExpression safeValue(QStringLiteral("^[A-Za-z0-9_./:@+-]*$"));
    for (const QString& name : names) {
        if (env.contains(name) && safeValue.match(env.value(name)).hasMatch())
            args << name + QLatin1Char('=') + env.value(name);
    }
    args << exe;
    return QProcess::startDetached(QStringLiteral("pkexec"), args);
#endif
}

QString dataDir()
{
#ifdef Q_OS_WIN
    return qEnvironmentVariable("ProgramData", QStringLiteral("C:/ProgramData")) + QStringLiteral("/SecurityDNS");
#else
    return QStringLiteral("/var/lib/security-dns");
#endif
}

QString binDir() { return dataDir() + QStringLiteral("/bin"); }

#ifdef Q_OS_WIN
namespace {
void runHidden(const QString& program, const QStringList& args)
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(args);
    process.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* a) { a->flags |= CREATE_NO_WINDOW; });
    process.start();
    process.waitForFinished(60000);
}
} // namespace
#endif

void ensureDataDir()
{
    static bool done = false;
    if (done)
        return;
    QDir().mkpath(dataDir());
    QDir().mkpath(binDir());
    if (!isElevated())
        return;      // only an administrator can (and needs to) change the permissions
#ifdef Q_OS_WIN
    runHidden(QStringLiteral("icacls.exe"), {dataDir(), QStringLiteral("/setowner"), QStringLiteral("*S-1-5-32-544"), QStringLiteral("/T"), QStringLiteral("/C")});
    runHidden(QStringLiteral("icacls.exe"), {dataDir(), QStringLiteral("/inheritance:r"), QStringLiteral("/grant:r"),
                                             QStringLiteral("*S-1-5-18:(OI)(CI)F"), QStringLiteral("*S-1-5-32-544:(OI)(CI)F"),
                                             QStringLiteral("/T"), QStringLiteral("/C")});
    // Users may read the bin folder because the autostart launcher runs SpoofDPI as the signed-in user.
    runHidden(QStringLiteral("icacls.exe"), {binDir(), QStringLiteral("/grant"), QStringLiteral("*S-1-5-32-545:(OI)(CI)RX"), QStringLiteral("/C")});
#endif
    done = true;
}

QString exeSuffix()
{
#ifdef Q_OS_WIN
    return QStringLiteral(".exe");
#else
    return QString();
#endif
}

QString findTool(const QString& name)
{
    const QString found = QStandardPaths::findExecutable(name);
    if (!found.isEmpty())
        return found;
#ifndef Q_OS_WIN
    // pkexec and systemd services use a short PATH, so check the usual folders too.
    const QStringList extra = {QStringLiteral("/usr/local/sbin"), QStringLiteral("/usr/local/bin"),
                               QStringLiteral("/usr/sbin"), QStringLiteral("/sbin"),
                               QStringLiteral("/usr/bin"), QStringLiteral("/bin")};
    return QStandardPaths::findExecutable(name, extra);
#else
    return QString();
#endif
}

QString packageManager()
{
    for (const QString& pm : {QStringLiteral("apt-get"), QStringLiteral("dnf"),
                              QStringLiteral("pacman"), QStringLiteral("zypper")}) {
        if (!findTool(pm).isEmpty())
            return pm == QLatin1String("apt-get") ? QStringLiteral("apt") : pm;
    }
    return QString();
}

QString packageFor(const QString& command)
{
    const QString pm = packageManager();
    if (command == QLatin1String("curl") || command == QLatin1String("wget") || command == QLatin1String("tar"))
        return command;
    if (command == QLatin1String("gpg") || command == QLatin1String("gpg2")) {
        if (pm == QLatin1String("dnf")) return QStringLiteral("gnupg2");
        if (pm == QLatin1String("zypper")) return QStringLiteral("gpg2");
        return QStringLiteral("gnupg");
    }
    if (command == QLatin1String("wg") || command == QLatin1String("wg-quick"))
        return QStringLiteral("wireguard-tools");
    if (command == QLatin1String("runuser")) return QStringLiteral("util-linux");
    if (command == QLatin1String("timeout")) return QStringLiteral("coreutils");
    if (command == QLatin1String("journalctl") || command == QLatin1String("systemctl"))
        return QStringLiteral("systemd");
    if (command == QLatin1String("resolvectl"))
        return pm == QLatin1String("apt") ? QStringLiteral("systemd-resolved") : QStringLiteral("systemd");
    return QString();
}

QString startupFolder()
{
#ifdef Q_OS_WIN
    return QStandardPaths::writableLocation(QStandardPaths::ApplicationsLocation) + QStringLiteral("/Startup");
#else
    return QString();
#endif
}

} // namespace sdns::platform
