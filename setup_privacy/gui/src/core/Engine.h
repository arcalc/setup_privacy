#pragma once

#include "Settings.h"
#include "SystemConfig.h"
#include "ToolManager.h"
#include "Types.h"

#include <QObject>

#include <functional>

namespace sdns {

// Runs all long operations. Create it in the main thread, then move it to a worker
// thread and call its slots with queued connections. It never touches widgets:
// the UI listens to its signals, and the error dialog is reached through the
// problem handler.
class Engine : public QObject {
    Q_OBJECT
public:
    explicit Engine(const Settings& settings, QObject* parent = nullptr);

    // Called from the worker thread when a recoverable problem is found. The handler
    // must show the dialog (it may block) and return the user's choice.
    void setProblemHandler(std::function<FixChoice(const Problem&)> handler);

public slots:
    void applyPreset(int mode);                        // 1 SpoofDPI, 2 WARP, 3 WireGuard
    void performToolAction(int tool, int action);      // Tool / ToolAction values
    void killSwitch();                                 // stop every tool, keep encrypted DNS
    void restoreOriginal();                            // undo DNS/proxy changes, keep app and tools
    void installMissing();
    void updateTools();
    void refreshStatus();
    void updateSettings(const sdns::Settings& settings);

signals:
    void logLine(const QString& line);
    void busyChanged(bool busy);
    void statusReady(const sdns::StatusInfo& status);
    void operationFinished(bool ok, const QString& summary);
    void settingsChanged(const sdns::Settings& settings);
    void openSettingsRequested();
    void relaunchRequested();

private:
    bool runOperation(const QString& label, const std::function<void()>& body, bool withRecovery);
    void runGuarded(const std::function<void()>& step);
    FixOutcome applyFix(const Problem& problem, bool alternate);

    void ensurePrepared();                // backup once, then make sure encrypted DNS is on
    void ensureInstalled(Tool tool);
    void startTool(Tool tool);
    void stopTool(Tool tool);
    void stopEverything(QStringList* failures);
    void saveAndNotify();

    Settings m_settings;
    SystemConfig m_sys;
    ToolManager m_tools;
    std::function<FixChoice(const Problem&)> m_askUser;
    bool m_skipSystemDns = false;
};

} // namespace sdns
