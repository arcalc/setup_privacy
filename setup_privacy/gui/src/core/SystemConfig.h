#pragma once

#include "Settings.h"

#include <QJsonObject>

namespace sdns {

// Reads, changes, and restores the system settings this app touches:
// encrypted DNS (DoT on Linux, DoH on Windows) and the system proxy.
// All methods block and throw OperationError, so call them from the worker thread.
class SystemConfig {
public:
    explicit SystemConfig(const Settings& settings) : m_s(settings) {}

    // Captures the current DNS and proxy state so Restore can put it back exactly.
    QJsonObject snapshot();

    // Turns encrypted DNS on with leak protection. Returns false when it was skipped
    // (Windows build too old and allowSkip is true).
    bool enableEncryptedDns(bool allowSkip);
    bool isEncryptedDnsActive();

    // Points the system proxy at 127.0.0.1:port, or turns that off again.
    void enableProxy(int port);
    void disableProxy();

    // Restores everything captured by snapshot().
    void restore(const QJsonObject& snapshot);

private:
    const Settings& m_s;
};

} // namespace sdns
