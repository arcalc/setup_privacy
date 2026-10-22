#include "HttpClient.h"

#include "Types.h"

#include <QEventLoop>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace sdns {

HttpClient::HttpClient(int timeoutSec, const QString& githubToken)
    : m_timeoutSec(timeoutSec), m_token(githubToken)
{
}

QByteArray HttpClient::get(const QUrl& url) { return fetch(url, QString()); }

void HttpClient::download(const QUrl& url, const QString& destinationFile)
{
    fetch(url, destinationFile);
}

QByteArray HttpClient::fetch(const QUrl& url, const QString& destinationFile)
{
    QNetworkAccessManager manager;
    QNetworkRequest request(url);
    request.setRawHeader("User-Agent", "security-dns-gui");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setTransferTimeout(m_timeoutSec * 1000);

    if (url.host() == QLatin1String("api.github.com")) {
        request.setRawHeader("Accept", "application/vnd.github+json");
        if (!m_token.isEmpty())
            request.setRawHeader("Authorization", QByteArray("Bearer ") + m_token.toUtf8());
    }

    QNetworkReply* reply = manager.get(request);

    QFile file;
    if (!destinationFile.isEmpty()) {
        file.setFileName(destinationFile);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            reply->abort();
            reply->deleteLater();
            throw OperationError(makeProblem(ProblemKind::PermissionDenied,
                                             QStringLiteral("Permission denied: cannot write %1").arg(destinationFile)));
        }
        QObject::connect(reply, &QNetworkReply::readyRead, reply, [&]() { file.write(reply->readAll()); });
    }

    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    QByteArray body;
    if (destinationFile.isEmpty())
        body = reply->readAll();
    else {
        file.write(reply->readAll());
        file.close();
    }

    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QNetworkReply::NetworkError error = reply->error();
    const QString errorText = reply->errorString();
    const QString remaining = reply->rawHeader("X-RateLimit-Remaining");
    reply->deleteLater();

    if (error == QNetworkReply::NoError)
        return body;

    const QString detail = QStringLiteral("%1 (HTTP %2) %3").arg(errorText).arg(status).arg(url.toString());
    if (status == 429 || (status == 403 && (remaining == QLatin1String("0") || url.host() == QLatin1String("api.github.com"))))
        throw OperationError(makeProblem(ProblemKind::RateLimited, detail));
    if (status == 403 || status == 401)
        throw OperationError(makeProblem(ProblemKind::PermissionDenied, detail));
    if (error == QNetworkReply::TimeoutError || error == QNetworkReply::HostNotFoundError
        || error == QNetworkReply::ConnectionRefusedError || error == QNetworkReply::RemoteHostClosedError
        || error == QNetworkReply::TemporaryNetworkFailureError || error == QNetworkReply::NetworkSessionFailedError
        || error == QNetworkReply::UnknownNetworkError || error == QNetworkReply::OperationCanceledError)
        throw OperationError(makeProblem(ProblemKind::NetworkTimeout, detail));
    throw OperationError(makeProblem(ProblemKind::Unknown, detail));
}

ReleaseInfo HttpClient::latestRelease(const QString& ownerRepo)
{
    const QUrl url(QStringLiteral("https://api.github.com/repos/%1/releases/latest").arg(ownerRepo));
    const QJsonObject root = QJsonDocument::fromJson(get(url)).object();

    ReleaseInfo info;
    info.tag = root.value(QStringLiteral("tag_name")).toString();
    const QJsonArray assets = root.value(QStringLiteral("assets")).toArray();
    for (const QJsonValue& value : assets) {
        const QJsonObject a = value.toObject();
        ReleaseAsset asset;
        asset.name = a.value(QStringLiteral("name")).toString();
        asset.url = QUrl(a.value(QStringLiteral("browser_download_url")).toString());
        info.assets.append(asset);
    }
    if (info.tag.isEmpty())
        throw OperationError(makeProblem(ProblemKind::Unknown,
                                         QStringLiteral("Unexpected GitHub response for %1").arg(ownerRepo)));
    return info;
}

} // namespace sdns
