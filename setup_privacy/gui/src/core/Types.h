#pragma once

#include <QMetaType>
#include <QString>
#include <QThread>
#include <QVariantMap>

#include <atomic>
#include <stdexcept>
#include <utility>

namespace sdns {

enum class Tool { SpoofDpi = 0, Warp = 1, WireGuard = 2 };

enum class ToolAction { Install = 0, Start = 1, Stop = 2, Enable = 3, Disable = 4, Uninstall = 5 };

// Every failure the app can recognize. Each kind has a translated title,
// explanation, and proposed fix in the i18n files (problem.<key>.*).
enum class ProblemKind {
    PortInUse,
    UnsupportedFlag,
    MissingResolvconf,
    MissingTool,
    PermissionDenied,
    NetworkTimeout,
    RateLimited,
    ResolvedMissing,
    AssetNotFound,
    ChecksumMismatch,
    ToolConflict,
    UnsupportedWindowsBuild,
    Unknown
};

inline QString problemKey(ProblemKind kind)
{
    switch (kind) {
    case ProblemKind::PortInUse: return QStringLiteral("port_in_use");
    case ProblemKind::UnsupportedFlag: return QStringLiteral("unsupported_flag");
    case ProblemKind::MissingResolvconf: return QStringLiteral("missing_resolvconf");
    case ProblemKind::MissingTool: return QStringLiteral("missing_tool");
    case ProblemKind::PermissionDenied: return QStringLiteral("permission");
    case ProblemKind::NetworkTimeout: return QStringLiteral("network");
    case ProblemKind::RateLimited: return QStringLiteral("ratelimit");
    case ProblemKind::ResolvedMissing: return QStringLiteral("resolved_missing");
    case ProblemKind::AssetNotFound: return QStringLiteral("no_asset");
    case ProblemKind::ChecksumMismatch: return QStringLiteral("checksum");
    case ProblemKind::ToolConflict: return QStringLiteral("conflict");
    case ProblemKind::UnsupportedWindowsBuild: return QStringLiteral("doh_unsupported");
    case ProblemKind::Unknown: break;
    }
    return QStringLiteral("unknown");
}

struct Problem {
    ProblemKind kind = ProblemKind::Unknown;
    QString detail;       // raw output or error text, shown under "Technical details"
    QVariantMap params;   // values used in the translated texts: port, tool, other, package
};

// What the user picked in the error dialog.
enum class FixChoice { Cancel, Primary, Alternate };

// What an automatic fix tells the operation to do next.
enum class FixOutcome { Resume, Stop };

class OperationError : public std::runtime_error {
public:
    explicit OperationError(Problem p)
        : std::runtime_error(p.detail.toStdString()), problem(std::move(p)) {}
    Problem problem;
};

class OperationCancelled : public std::runtime_error {
public:
    OperationCancelled() : std::runtime_error("cancelled") {}
};

// Lets the window interrupt a running operation, so the kill switch is instant even while a long
// download or install is in progress. One flag is enough because only one operation runs at a time.
class CancelToken {
public:
    void request() { m_requested.store(true); }
    void reset() { m_requested.store(false); }
    bool requested() const { return m_requested.load(); }

private:
    std::atomic<bool> m_requested{false};
};

inline CancelToken& cancelToken()
{
    static CancelToken token;
    return token;
}

inline void throwIfCancelled()
{
    if (cancelToken().requested())
        throw OperationCancelled();
}

// Sleeps in short steps so a cancel request is noticed within a fraction of a second.
inline void interruptibleSleep(int milliseconds)
{
    for (int waited = 0; waited < milliseconds; waited += 100) {
        throwIfCancelled();
        QThread::msleep(100);
    }
    throwIfCancelled();
}

struct ToolStatus {
    bool installed = false;
    bool running = false;
    bool enabled = false;
    QString version;
};

struct StatusInfo {
    ToolStatus spoof;
    ToolStatus warp;
    ToolStatus wireguard;
    bool dnsEncrypted = false;
    bool elevated = false;
    int spoofPort = 0;
};

inline Problem makeProblem(ProblemKind kind, const QString& detail, const QVariantMap& params = {})
{
    Problem p;
    p.kind = kind;
    p.detail = detail;
    p.params = params;
    return p;
}

} // namespace sdns

Q_DECLARE_METATYPE(sdns::StatusInfo)
