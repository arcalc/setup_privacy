#include "Settings.h"

#include "Platform.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>

namespace sdns {

namespace {

QString settingsPath() { return platform::dataDir() + QStringLiteral("/settings.json"); }
QString statePath() { return platform::dataDir() + QStringLiteral("/state.json"); }

QJsonObject readJson(const QString& path)
{
    platform::ensureDataDir();   // lock the folder down before reading anything from it
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return QJsonDocument::fromJson(file.readAll()).object();
}

void writeJson(const QString& path, const QJsonObject& object)
{
    platform::ensureDataDir();
    // QSaveFile writes to a temporary file and renames it, so a crash or power loss can never leave
    // half a file. This matters because state.json holds the only copy of your original settings.
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly))
        return;
    file.write(QJsonDocument(object).toJson(QJsonDocument::Indented));
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    file.commit();
}

} // namespace

Settings Settings::defaults()
{
    Settings s;
#ifdef Q_OS_WIN
    s.dnsServers = {QStringLiteral("1.1.1.1"), QStringLiteral("1.0.0.1"),
                    QStringLiteral("2606:4700:4700::1111"), QStringLiteral("2606:4700:4700::1001")};
#else
    s.dnsServers = {QStringLiteral("1.1.1.1"), QStringLiteral("1.0.0.1")};
#endif
    return s;
}

Settings Settings::load()
{
    Settings s = defaults();
    const QJsonObject o = readJson(settingsPath());
    if (o.isEmpty())
        return s;

    s.language = o.value(QStringLiteral("language")).toString(s.language);
    s.theme = o.value(QStringLiteral("theme")).toString(s.theme);
    s.spoofPort = o.value(QStringLiteral("spoofPort")).toInt(s.spoofPort);
    s.spoofArgStyle = o.value(QStringLiteral("spoofArgStyle")).toString(s.spoofArgStyle);
    s.spoofExtraArgs = o.value(QStringLiteral("spoofExtraArgs")).toString();
    s.spoofPath = o.value(QStringLiteral("spoofPath")).toString();
    s.wgcfPath = o.value(QStringLiteral("wgcfPath")).toString();
    s.wgQuickPath = o.value(QStringLiteral("wgQuickPath")).toString();
    s.warpCliPath = o.value(QStringLiteral("warpCliPath")).toString();
    s.dohTemplate = o.value(QStringLiteral("dohTemplate")).toString(s.dohTemplate);
    s.wgEndpoint = o.value(QStringLiteral("wgEndpoint")).toString();
    s.wgStripDns = o.value(QStringLiteral("wgStripDns")).toBool(s.wgStripDns);
    s.manageSystemProxy = o.value(QStringLiteral("manageSystemProxy")).toBool(s.manageSystemProxy);
    s.networkTimeoutSec = o.value(QStringLiteral("networkTimeoutSec")).toInt(s.networkTimeoutSec);
    s.githubToken = o.value(QStringLiteral("githubToken")).toString();

    const QJsonArray servers = o.value(QStringLiteral("dnsServers")).toArray();
    if (!servers.isEmpty()) {
        QStringList valid;
        static const QRegularExpression serverRe(QStringLiteral("^[0-9A-Fa-f:.]+(#[A-Za-z0-9.-]+)?$"));
        for (const QJsonValue& v : servers) {
            if (serverRe.match(v.toString()).hasMatch())
                valid << v.toString();
        }
        if (!valid.isEmpty())
            s.dnsServers = valid;   // anything invalid in a hand-edited file is ignored
    }

    // Clamp or reset anything out of range, so a hand-edited file can never cause surprises.
    s.spoofPort = qBound(1, s.spoofPort, 65535);
    s.networkTimeoutSec = qBound(5, s.networkTimeoutSec, 300);
    static const QStringList styles = {QStringLiteral("auto"), QStringLiteral("listen"), QStringLiteral("config"),
                                       QStringLiteral("flags"), QStringLiteral("port"), QStringLiteral("none")};
    if (!styles.contains(s.spoofArgStyle))
        s.spoofArgStyle = QStringLiteral("auto");
    if (s.theme != QLatin1String("dark") && s.theme != QLatin1String("light"))
        s.theme = QStringLiteral("dark");
    if (s.language != QLatin1String("en") && s.language != QLatin1String("ar"))
        s.language = QStringLiteral("en");
    static const QRegularExpression safeArgs(QStringLiteral("^[A-Za-z0-9 ._=:/@,+-]*$"));
    if (!safeArgs.match(s.spoofExtraArgs).hasMatch())
        s.spoofExtraArgs.clear();
    static const QRegularExpression endpointRe(QStringLiteral("^[\\[\\]A-Za-z0-9._:-]+:\\d{1,5}$"));
    if (!s.wgEndpoint.isEmpty() && !endpointRe.match(s.wgEndpoint).hasMatch())
        s.wgEndpoint.clear();
    return s;
}

void Settings::save() const
{
    QJsonObject o;
    o[QStringLiteral("language")] = language;
    o[QStringLiteral("theme")] = theme;
    o[QStringLiteral("spoofPort")] = spoofPort;
    o[QStringLiteral("spoofArgStyle")] = spoofArgStyle;
    o[QStringLiteral("spoofExtraArgs")] = spoofExtraArgs;
    o[QStringLiteral("spoofPath")] = spoofPath;
    o[QStringLiteral("wgcfPath")] = wgcfPath;
    o[QStringLiteral("wgQuickPath")] = wgQuickPath;
    o[QStringLiteral("warpCliPath")] = warpCliPath;
    o[QStringLiteral("dohTemplate")] = dohTemplate;
    o[QStringLiteral("wgEndpoint")] = wgEndpoint;
    o[QStringLiteral("wgStripDns")] = wgStripDns;
    o[QStringLiteral("manageSystemProxy")] = manageSystemProxy;
    o[QStringLiteral("networkTimeoutSec")] = networkTimeoutSec;
    o[QStringLiteral("githubToken")] = githubToken;
    o[QStringLiteral("dnsServers")] = QJsonArray::fromStringList(dnsServers);
    writeJson(settingsPath(), o);
}

bool StateStore::has(const QString& key) { return readJson(statePath()).contains(key); }

QJsonValue StateStore::get(const QString& key) { return readJson(statePath()).value(key); }

QString StateStore::str(const QString& key) { return get(key).toString(); }

bool StateStore::flag(const QString& key) { return get(key).toBool(false); }

void StateStore::set(const QString& key, const QJsonValue& value)
{
    QJsonObject o = readJson(statePath());
    o[key] = value;
    writeJson(statePath(), o);
}

void StateStore::remove(const QString& key)
{
    QJsonObject o = readJson(statePath());
    o.remove(key);
    writeJson(statePath(), o);
}

} // namespace sdns
