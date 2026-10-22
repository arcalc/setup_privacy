#include "Platform.h"

#include <QCoreApplication>
#include <QProcess>
#include <QProcessEnvironment>
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
    for (const QString& name : names) {
        if (env.contains(name))
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
