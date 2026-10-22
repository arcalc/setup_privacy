#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QUrl>

namespace sdns {

struct ReleaseAsset {
    QString name;
    QUrl url;
};

struct ReleaseInfo {
    QString tag;
    QList<ReleaseAsset> assets;
};

// Blocking HTTP helper. Must be used from a thread that runs an event loop or
// from a worker thread; it never touches widgets. Throws OperationError.
class HttpClient {
public:
    HttpClient(int timeoutSec, const QString& githubToken);

    // Latest release of "owner/repo" from the GitHub API.
    ReleaseInfo latestRelease(const QString& ownerRepo);

    QByteArray get(const QUrl& url);
    void download(const QUrl& url, const QString& destinationFile);

private:
    QByteArray fetch(const QUrl& url, const QString& destinationFile);

    int m_timeoutSec;
    QString m_token;
};

} // namespace sdns
