#include "CommandRunner.h"

#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace sdns {

CommandResult CommandRunner::run(const QString& program, const QStringList& args, int timeoutMs,
                                 const QByteArray& input, const QString& workDir)
{
    CommandResult result;
    QProcess process;
    process.setProgram(program);
    process.setArguments(args);
    if (!workDir.isEmpty())
        process.setWorkingDirectory(workDir);
#ifdef Q_OS_WIN
    process.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* a) {
        a->flags |= CREATE_NO_WINDOW;
    });
#endif

    process.start();
    if (!process.waitForStarted(5000)) {
        result.err = process.errorString();
        return result;
    }
    result.started = true;

    if (!input.isEmpty())
        process.write(input);
    process.closeWriteChannel();

    if (!process.waitForFinished(timeoutMs)) {
        result.timedOut = true;
        process.kill();
        process.waitForFinished(2000);
    }
    result.exitCode = process.exitCode();
    result.out = QString::fromUtf8(process.readAllStandardOutput());
    result.err = QString::fromUtf8(process.readAllStandardError());
    return result;
}

CommandResult CommandRunner::runChecked(const QString& program, const QStringList& args, int timeoutMs,
                                        const QByteArray& input, const QString& workDir)
{
    const CommandResult result = run(program, args, timeoutMs, input, workDir);
    if (!result.ok())
        throw OperationError(analyzer::classify(program, result));
    return result;
}

CommandResult CommandRunner::runPowerShell(const QString& script, int timeoutMs)
{
    // -EncodedCommand takes base64 UTF-16LE, which avoids every quoting problem.
    const QByteArray bytes(reinterpret_cast<const char*>(script.utf16()), static_cast<int>(script.size() * 2));
    const QStringList args = {QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"),
                              QStringLiteral("-ExecutionPolicy"), QStringLiteral("Bypass"),
                              QStringLiteral("-EncodedCommand"), QString::fromLatin1(bytes.toBase64())};
    return run(QStringLiteral("powershell.exe"), args, timeoutMs);
}

CommandResult CommandRunner::runPowerShellChecked(const QString& script, int timeoutMs)
{
    const CommandResult result = runPowerShell(script, timeoutMs);
    if (!result.ok())
        throw OperationError(analyzer::classify(QStringLiteral("powershell.exe"), result));
    return result;
}

namespace analyzer {

namespace {

bool contains(const QString& text, const char* pattern)
{
    const QRegularExpression re(QString::fromLatin1(pattern), QRegularExpression::CaseInsensitiveOption);
    return re.match(text).hasMatch();
}

} // namespace

Problem classifyText(const QString& text)
{
    Problem p;
    p.detail = text;

    // Order matters: the most specific patterns come first.
    if (contains(text, "conflict:(warp|wireguard)")) {
        p.kind = ProblemKind::ToolConflict;
        const QRegularExpressionMatch m = QRegularExpression(
            QStringLiteral("conflict:(warp|wireguard)"), QRegularExpression::CaseInsensitiveOption).match(text);
        p.params[QStringLiteral("other")] = m.captured(1).toLower();
    } else if (contains(text, "doh-unsupported")) {
        p.kind = ProblemKind::UnsupportedWindowsBuild;
    } else if (contains(text, "address already in use|only one usage of each socket|already in use")) {
        p.kind = ProblemKind::PortInUse;
        const QRegularExpressionMatch m = QRegularExpression(QStringLiteral(":(\\d{2,5})\\b")).match(text);
        if (m.hasMatch())
            p.params[QStringLiteral("port")] = m.captured(1);
    } else if (contains(text, "flag provided but not defined|unknown flag|unknown option|unrecognized option|unknown shorthand")) {
        p.kind = ProblemKind::UnsupportedFlag;
    } else if (contains(text, "resolvconf: (command )?not found|resolvconf.*not found|openresolv")) {
        p.kind = ProblemKind::MissingResolvconf;
        p.params[QStringLiteral("package")] = QStringLiteral("resolvconf / openresolv");
    } else if (contains(text, "systemd-resolved.*(not found|could not be found|not-found)|resolvectl: (command )?not found|stub file not found")) {
        p.kind = ProblemKind::ResolvedMissing;
    } else if (contains(text, "no .* asset found")) {
        p.kind = ProblemKind::AssetNotFound;
    } else if (contains(text, "checksum|sha-?256 mismatch")) {
        p.kind = ProblemKind::ChecksumMismatch;
    } else if (contains(text, "rate limit|http 403|403 forbidden|error: 403|error: 429")) {
        p.kind = ProblemKind::RateLimited;
    } else if (contains(text, "could not resolve host|name or service not known|timed out|timeout|connection refused|network is unreachable|temporary failure in name resolution|host not found|no such host")) {
        p.kind = ProblemKind::NetworkTimeout;
    } else if (contains(text, "permission denied|operation not permitted|access is denied|must be run as root")) {
        p.kind = ProblemKind::PermissionDenied;
    } else if (contains(text, "command not found|: not found|no such file or directory|program not found")) {
        p.kind = ProblemKind::MissingTool;
        const QRegularExpressionMatch m = QRegularExpression(
            QStringLiteral("([A-Za-z0-9_.+-]+): (command )?not found")).match(text);
        if (m.hasMatch())
            p.params[QStringLiteral("tool")] = m.captured(1);
    } else {
        p.kind = ProblemKind::Unknown;
    }
    return p;
}

Problem classify(const QString& program, const CommandResult& result)
{
    if (!result.started) {
        Problem p;
        p.kind = ProblemKind::MissingTool;
        p.detail = QStringLiteral("%1: command not found (%2)").arg(QFileInfo(program).fileName(), result.err);
        p.params[QStringLiteral("tool")] = QFileInfo(program).fileName();
        return p;
    }
    if (result.timedOut) {
        Problem p;
        p.kind = ProblemKind::NetworkTimeout;
        p.detail = QStringLiteral("%1 timed out").arg(QFileInfo(program).fileName());
        return p;
    }
    Problem p = classifyText(result.combined());
    if (p.kind == ProblemKind::MissingTool && !p.params.contains(QStringLiteral("tool")))
        p.params[QStringLiteral("tool")] = QFileInfo(program).fileName();
    if (p.detail.isEmpty())
        p.detail = QStringLiteral("%1 failed (exit code %2)").arg(QFileInfo(program).fileName()).arg(result.exitCode);
    return p;
}

} // namespace analyzer

} // namespace sdns
