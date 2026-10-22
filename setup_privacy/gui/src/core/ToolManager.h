#pragma once

#include "Settings.h"
#include "Types.h"

#include <QStringList>

#include <functional>

namespace sdns {

using LogFn = std::function<void(const QString&)>;

// Controls SpoofDPI, Cloudflare WARP, and WireGuard (wgcf) one by one:
// install, start, stop, enable (autostart), disable, uninstall.
// Methods block and throw OperationError, so call them from the worker thread.
// This class does not touch DNS or the system proxy; the Engine does that.
class ToolManager {
public:
    ToolManager(const Settings& settings, LogFn log);

    ToolStatus status(Tool tool);
    void perform(Tool tool, ToolAction action);

    // The port SpoofDPI will really use (builds without a port option stay on 8080).
    int spoofEffectivePort();

    // Installs system packages with the detected package manager (Linux).
    void installPackages(const QStringList& packages);

    // First free local port at or after start (0 when none is found nearby).
    static int freePortNear(int start);

private:
    void log(const QString& message) const;

    // SpoofDPI
    QString spoofBin() const;
    QString spoofStyle();
    QStringList spoofArgs(int port);
    ToolStatus spoofStatus();
    void spoofInstall();
    void spoofStart();
    void spoofStop();
    void spoofEnable();
    void spoofDisable();
    void spoofUninstall();

    // Cloudflare WARP
    QString warpCli() const;
    ToolStatus warpStatus();
    void warpInstall();
    void warpStart();
    void warpStop();
    void warpEnable();
    void warpDisable();
    void warpUninstall();

    // WireGuard with a wgcf profile
    QString wgConfPath() const;
    QString wgcfBin() const;
    QString wgQuick() const;
    QString wireguardExe() const;
    ToolStatus wgStatus();
    void wgInstall();
    void wgWriteConf();
    void wgStart();
    void wgStop();
    void wgEnable();
    void wgDisable();
    void wgUninstall();

    void removePackages(const QStringList& packages);

    const Settings& m_s;
    LogFn m_log;
};

} // namespace sdns
