#include "Engine.h"

#include "CommandRunner.h"
#include "Platform.h"
#include "Translator.h"

#include <QMap>
#include <QThread>

namespace sdns {

namespace {

constexpr int kMaxAttemptsPerProblem = 3;

QString toolName(Tool tool)
{
    switch (tool) {
    case Tool::SpoofDpi: return QStringLiteral("SpoofDPI");
    case Tool::Warp: return QStringLiteral("Cloudflare WARP");
    case Tool::WireGuard: return QStringLiteral("WireGuard (wgcf)");
    }
    return QString();
}

QString actionName(ToolAction action)
{
    switch (action) {
    case ToolAction::Install: return QStringLiteral("install");
    case ToolAction::Start: return QStringLiteral("start");
    case ToolAction::Stop: return QStringLiteral("stop");
    case ToolAction::Enable: return QStringLiteral("enable");
    case ToolAction::Disable: return QStringLiteral("disable");
    case ToolAction::Uninstall: return QStringLiteral("uninstall");
    }
    return QString();
}

} // namespace

Engine::Engine(const Settings& settings, QObject* parent)
    : QObject(parent),
      m_settings(settings),
      m_sys(m_settings),
      m_tools(m_settings, [this](const QString& line) { emit logLine(line); })
{
}

void Engine::setProblemHandler(std::function<FixChoice(const Problem&)> handler)
{
    m_askUser = std::move(handler);
}

void Engine::saveAndNotify()
{
    m_settings.save();
    emit settingsChanged(m_settings);
}

void Engine::updateSettings(const Settings& settings)
{
    // New DNS servers or DoH template must be applied the next time a tool starts.
    if (settings.dnsServers != m_settings.dnsServers || settings.dohTemplate != m_settings.dohTemplate)
        StateStore::set(QStringLiteral("dnsStale"), true);
    m_settings = settings;
    m_settings.save();
}

// -----------------------------------------------------------------------------
// Recovery: detect the failure, explain it, apply the fix the user approves,
// then resume the same operation.
// -----------------------------------------------------------------------------
void Engine::runGuarded(const std::function<void()>& step)
{
    QMap<int, int> attempts;
    while (true) {
        try {
            step();
            return;
        } catch (const OperationCancelled&) {
            throw;
        } catch (const OperationError& error) {
            const Problem problem = error.problem;
            emit logLine(problem.detail.trimmed());

            const int key = static_cast<int>(problem.kind);
            attempts[key] += 1;
            if (attempts[key] > kMaxAttemptsPerProblem) {
                emit logLine(T(QStringLiteral("log.giving_up")));
                throw;
            }

            const FixChoice choice = m_askUser ? m_askUser(problem) : FixChoice::Cancel;
            if (choice == FixChoice::Cancel)
                throw OperationCancelled();

            const FixOutcome outcome = applyFix(problem, choice == FixChoice::Alternate);
            if (outcome == FixOutcome::Stop)
                throw OperationCancelled();
            emit logLine(T(QStringLiteral("log.fix_applied")));
        }
    }
}

FixOutcome Engine::applyFix(const Problem& problem, bool alternate)
{
    switch (problem.kind) {
    case ProblemKind::PortInUse: {
        const int next = ToolManager::freePortNear(m_settings.spoofPort + 1);
        if (next == 0)
            throw OperationError(makeProblem(ProblemKind::Unknown, QStringLiteral("No free port was found near %1.").arg(m_settings.spoofPort)));
        m_settings.spoofPort = next;
        saveAndNotify();
        emit logLine(T(QStringLiteral("log.port_switched"), {{QStringLiteral("port"), next}}));
        break;
    }
    case ProblemKind::UnsupportedFlag: {
        static const QStringList order = {QStringLiteral("auto"), QStringLiteral("config"), QStringLiteral("flags"),
                                          QStringLiteral("port"), QStringLiteral("none")};
        const int index = order.indexOf(m_settings.spoofArgStyle);
        m_settings.spoofArgStyle = order.at((index + 1) % order.size());
        saveAndNotify();
        emit logLine(QStringLiteral("SpoofDPI argument style: %1").arg(m_settings.spoofArgStyle));
        break;
    }
    case ProblemKind::MissingResolvconf:
        if (alternate) {
            m_settings.wgStripDns = true;   // let this app handle DNS, so resolvconf is not needed
            saveAndNotify();
        } else {
            m_tools.installPackages({platform::packageManager() == QLatin1String("apt") ? QStringLiteral("resolvconf")
                                                                                          : QStringLiteral("openresolv")});
            m_sys.enableEncryptedDns(m_skipSystemDns);   // installing resolvconf can replace /etc/resolv.conf
        }
        break;
    case ProblemKind::MissingTool: {
        const QString tool = problem.params.value(QStringLiteral("tool")).toString();
        if (tool == QLatin1String("warp-cli")) {
            m_tools.perform(Tool::Warp, ToolAction::Install);
        } else if (tool == QLatin1String("wgcf") || tool == QLatin1String("wg-quick") || tool == QLatin1String("wg")) {
            m_tools.perform(Tool::WireGuard, ToolAction::Install);
        } else if (tool.startsWith(QLatin1String("spoof"))) {
            m_tools.perform(Tool::SpoofDpi, ToolAction::Install);
        } else {
            const QString package = platform::packageFor(tool);
            if (package.isEmpty()) {
                emit logLine(QStringLiteral("No package is known for the missing program: %1").arg(tool));
                return FixOutcome::Stop;
            }
            m_tools.installPackages({package});
        }
        break;
    }
    case ProblemKind::PermissionDenied:
        if (!platform::isElevated()) {
            if (platform::relaunchElevated())
                emit relaunchRequested();
            return FixOutcome::Stop;
        }
        break;
    case ProblemKind::NetworkTimeout:
        m_settings.networkTimeoutSec = qMin(120, m_settings.networkTimeoutSec * 2);
        saveAndNotify();
        QThread::sleep(3);
        break;
    case ProblemKind::RateLimited:
        emit logLine(T(QStringLiteral("log.waiting_30")));
        QThread::sleep(30);
        break;
    case ProblemKind::ResolvedMissing:
        if (platform::packageManager() != QLatin1String("pacman")) {
            try { m_tools.installPackages({QStringLiteral("systemd-resolved")}); }
            catch (const OperationError&) { /* part of systemd on some distributions */ }
        }
        CommandRunner::runChecked(QStringLiteral("systemctl"), {QStringLiteral("enable"), QStringLiteral("--now"), QStringLiteral("systemd-resolved")});
        break;
    case ProblemKind::AssetNotFound:
        emit openSettingsRequested();
        return FixOutcome::Stop;
    case ProblemKind::ChecksumMismatch:
        break;   // downloads are never cached, so retrying fetches a fresh copy
    case ProblemKind::ToolConflict: {
        const QString other = problem.params.value(QStringLiteral("other")).toString();
        if (other == QLatin1String("warp")) stopTool(Tool::Warp);
        else if (other == QLatin1String("wireguard")) stopTool(Tool::WireGuard);
        else return FixOutcome::Stop;
        break;
    }
    case ProblemKind::UnsupportedWindowsBuild:
        m_skipSystemDns = true;
        break;
    case ProblemKind::Unknown:
        break;
    }
    return FixOutcome::Resume;
}

bool Engine::runOperation(const QString& label, const std::function<void()>& body, bool withRecovery)
{
    emit busyChanged(true);
    emit logLine(QStringLiteral("== ") + label);

    bool ok = false;
    QString summary;
    try {
        if (withRecovery)
            runGuarded(body);
        else
            body();
        ok = true;
        summary = T(QStringLiteral("log.done"));
    } catch (const OperationCancelled&) {
        summary = T(QStringLiteral("log.cancelled"));
    } catch (const OperationError& error) {
        emit logLine(error.problem.detail.trimmed());
        summary = T(QStringLiteral("log.failed"));
    } catch (const std::exception& error) {
        emit logLine(QString::fromUtf8(error.what()));
        summary = T(QStringLiteral("log.failed"));
    }

    emit logLine(summary);
    emit busyChanged(false);
    emit operationFinished(ok, summary);
    refreshStatus();
    return ok;
}

// -----------------------------------------------------------------------------
// Building blocks
// -----------------------------------------------------------------------------
void Engine::ensurePrepared()
{
    if (!StateStore::has(QStringLiteral("backup"))) {
        StateStore::set(QStringLiteral("backup"), m_sys.snapshot());
        emit logLine(T(QStringLiteral("log.backup_done")));
    }
    if (StateStore::flag(QStringLiteral("dnsRestored")) || StateStore::flag(QStringLiteral("dnsStale"))
        || !StateStore::flag(QStringLiteral("dnsApplied"))) {
        const bool applied = m_sys.enableEncryptedDns(m_skipSystemDns);
        StateStore::set(QStringLiteral("dnsApplied"), applied);
        StateStore::set(QStringLiteral("dnsRestored"), false);
        StateStore::set(QStringLiteral("dnsStale"), false);
        emit logLine(applied ? T(QStringLiteral("log.dns_on")) : T(QStringLiteral("log.dns_skipped")));
    }
}

void Engine::ensureInstalled(Tool tool)
{
    if (!m_tools.status(tool).installed)
        m_tools.perform(tool, ToolAction::Install);
}

void Engine::startTool(Tool tool)
{
    ensurePrepared();
    m_tools.perform(tool, ToolAction::Start);
    if (tool == Tool::SpoofDpi && m_settings.manageSystemProxy) {
        m_sys.enableProxy(m_tools.spoofEffectivePort());
        StateStore::set(QStringLiteral("proxyManaged"), true);
    }
}

void Engine::stopTool(Tool tool)
{
    if (tool == Tool::SpoofDpi && StateStore::flag(QStringLiteral("proxyManaged"))) {
        m_sys.disableProxy();
        StateStore::set(QStringLiteral("proxyManaged"), false);
    }
    m_tools.perform(tool, ToolAction::Stop);
}

// Best effort: keeps going after a failure and reports what could not be stopped.
void Engine::stopEverything(QStringList* failures)
{
    auto attempt = [failures](const QString& name, const std::function<void()>& action) {
        try {
            action();
        } catch (const OperationError& error) {
            *failures << QStringLiteral("%1: %2").arg(name, error.problem.detail.trimmed());
        } catch (const std::exception& error) {
            *failures << QStringLiteral("%1: %2").arg(name, QString::fromUtf8(error.what()));
        }
    };
    attempt(QStringLiteral("proxy"), [this]() {
        if (StateStore::flag(QStringLiteral("proxyManaged"))) {
            m_sys.disableProxy();
            StateStore::set(QStringLiteral("proxyManaged"), false);
        }
    });
    attempt(QStringLiteral("WireGuard"), [this]() { m_tools.perform(Tool::WireGuard, ToolAction::Stop); });
    attempt(QStringLiteral("WARP"), [this]() { m_tools.perform(Tool::Warp, ToolAction::Stop); });
    attempt(QStringLiteral("SpoofDPI"), [this]() { m_tools.perform(Tool::SpoofDpi, ToolAction::Stop); });
}

// -----------------------------------------------------------------------------
// Operations (slots)
// -----------------------------------------------------------------------------
void Engine::applyPreset(int mode)
{
    const QString label = T(QStringLiteral("op.preset"), {{QStringLiteral("name"),
        mode == 1 ? toolName(Tool::SpoofDpi) : (mode == 2 ? toolName(Tool::Warp) : toolName(Tool::WireGuard))}});
    runOperation(label, [this, mode]() {
        switch (mode) {
        case 1:
            stopTool(Tool::WireGuard); stopTool(Tool::Warp);
            ensureInstalled(Tool::SpoofDpi); startTool(Tool::SpoofDpi);
            break;
        case 2:
            stopTool(Tool::SpoofDpi); stopTool(Tool::WireGuard);
            ensureInstalled(Tool::Warp); startTool(Tool::Warp);
            break;
        case 3:
            stopTool(Tool::SpoofDpi); stopTool(Tool::Warp);
            ensureInstalled(Tool::WireGuard); startTool(Tool::WireGuard);
            break;
        default:
            break;
        }
    }, true);
}

void Engine::performToolAction(int toolValue, int actionValue)
{
    const Tool tool = static_cast<Tool>(toolValue);
    const ToolAction action = static_cast<ToolAction>(actionValue);
    runOperation(QStringLiteral("%1: %2").arg(toolName(tool), actionName(action)), [this, tool, action]() {
        switch (action) {
        case ToolAction::Start: startTool(tool); break;
        case ToolAction::Stop: stopTool(tool); break;
        case ToolAction::Uninstall: stopTool(tool); m_tools.perform(tool, ToolAction::Uninstall); break;
        default: m_tools.perform(tool, action); break;
        }
    }, true);
}

void Engine::killSwitch()
{
    runOperation(T(QStringLiteral("op.kill")), [this]() {
        QStringList failures;
        stopEverything(&failures);
        try {
            m_sys.enableEncryptedDns(true);
            StateStore::set(QStringLiteral("dnsApplied"), true);
            StateStore::set(QStringLiteral("dnsRestored"), false);
        } catch (const OperationError& error) {
            failures << QStringLiteral("DNS: %1").arg(error.problem.detail.trimmed());
        }
        for (Tool tool : {Tool::SpoofDpi, Tool::Warp, Tool::WireGuard}) {
            if (m_tools.status(tool).running)
                failures << QStringLiteral("%1 is still running").arg(toolName(tool));
        }
        if (!failures.isEmpty())
            throw OperationError(makeProblem(ProblemKind::Unknown, failures.join(QLatin1Char('\n'))));
    }, false);
}

void Engine::restoreOriginal()
{
    runOperation(T(QStringLiteral("op.restore")), [this]() {
        QStringList failures;
        stopEverything(&failures);
        const QJsonObject snapshot = StateStore::get(QStringLiteral("backup")).toObject();
        if (snapshot.isEmpty())
            throw OperationError(makeProblem(ProblemKind::Unknown, T(QStringLiteral("log.no_backup"))));
        m_sys.restore(snapshot);
        StateStore::set(QStringLiteral("dnsRestored"), true);
        StateStore::set(QStringLiteral("proxyManaged"), false);
        emit logLine(T(QStringLiteral("log.restored")));
    }, true);
}

void Engine::installMissing()
{
    runOperation(T(QStringLiteral("op.install_missing")), [this]() {
        for (Tool tool : {Tool::SpoofDpi, Tool::Warp, Tool::WireGuard})
            ensureInstalled(tool);
    }, true);
}

void Engine::updateTools()
{
    runOperation(T(QStringLiteral("op.update")), [this]() {
        for (Tool tool : {Tool::SpoofDpi, Tool::WireGuard}) {
            const ToolStatus before = m_tools.status(tool);
            if (!before.installed)
                continue;
            m_tools.perform(tool, ToolAction::Install);   // skips when already up to date
            const ToolStatus after = m_tools.status(tool);
            if (before.running && after.version != before.version)
                startTool(tool);                          // restart on the new version
        }
        emit logLine(T(QStringLiteral("log.warp_self_update")));
    }, true);
}

void Engine::refreshStatus()
{
    StatusInfo info;
    info.spoof = m_tools.status(Tool::SpoofDpi);
    info.warp = m_tools.status(Tool::Warp);
    info.wireguard = m_tools.status(Tool::WireGuard);
    info.elevated = platform::isElevated();
    info.dnsEncrypted = StateStore::flag(QStringLiteral("dnsApplied")) && !StateStore::flag(QStringLiteral("dnsRestored"))
                        && m_sys.isEncryptedDnsActive();
    info.spoofPort = info.spoof.installed ? m_tools.spoofEffectivePort() : m_settings.spoofPort;
    emit statusReady(info);
}

} // namespace sdns
