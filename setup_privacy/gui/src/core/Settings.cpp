#include "Settings.h"

#include "Platform.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace sdns {

namespace {

QString settingsPath() { return platform::dataDir() + QStringLiteral("/settings.json"); }
QString statePath() { return platform::dataDir() + QStringLiteral("/state.json"); }

QJsonObject readJson(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return QJsonDocument::fromJson(file.readAll()).object();
}

void writeJson(const QString& path, const QJsonObject& object)
{
    QDir().mkpath(platform::dataDir());
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return;
    file.write(QJsonDocument(object).toJson(QJsonDocument::Indented));
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
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
        s.dnsServers.clear();
        for (const QJsonValue& v : servers)
            s.dnsServers << v.toString();
    }
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
