#pragma once

#include "Types.h"

#include <QByteArray>
#include <QString>
#include <QStringList>

namespace sdns {

struct CommandResult {
    bool started = false;    // false when the program could not be launched at all
    bool timedOut = false;   // true when it was stopped after the timeout
    int exitCode = -1;
    QString out;
    QString err;

    bool ok() const { return started && !timedOut && exitCode == 0; }
    QString combined() const { return (out + QLatin1Char('\n') + err).trimmed(); }
};

class CommandRunner {
public:
    // Runs a program and waits for it. Never throws.
    static CommandResult run(const QString& program, const QStringList& args, int timeoutMs = 30000,
                             const QByteArray& input = QByteArray(), const QString& workDir = QString());

    // Same as run(), but throws OperationError with a classified Problem on failure.
    static CommandResult runChecked(const QString& program, const QStringList& args, int timeoutMs = 30000,
                                    const QByteArray& input = QByteArray(), const QString& workDir = QString());

    // Windows: runs a PowerShell script (passed as an encoded command, so quoting is safe).
    static CommandResult runPowerShell(const QString& script, int timeoutMs = 60000);
    static CommandResult runPowerShellChecked(const QString& script, int timeoutMs = 60000);
};

namespace analyzer {

// Turns raw error text into a classified Problem (port conflict, missing tool, ...).
Problem classifyText(const QString& text);

// Classifies a failed command (handles "program not found" and timeouts too).
Problem classify(const QString& program, const CommandResult& result);

} // namespace analyzer

} // namespace sdns
