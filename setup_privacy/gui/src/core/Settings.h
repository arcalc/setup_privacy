#pragma once

#include <QJsonValue>
#include <QMetaType>
#include <QString>
#include <QStringList>

namespace sdns {

// Everything the user can customize in the Advanced Settings tab.
struct Settings {
    QString language = QStringLiteral("en");     // "en" or "ar"
    QString theme = QStringLiteral("dark");      // "dark" or "light"

    int spoofPort = 8080;                         // port SpoofDPI listens on (127.0.0.1)
    QString spoofArgStyle = QStringLiteral("auto"); // auto, config, flags, port, none
    QString spoofExtraArgs;                       // extra SpoofDPI command-line arguments

    QString spoofPath;                            // custom SpoofDPI program (empty = managed copy)
    QString wgcfPath;                             // custom wgcf program
    QString wgQuickPath;                          // custom wg-quick program (Linux)
    QString warpCliPath;                          // custom warp-cli program

    QStringList dnsServers;                       // encrypted DNS server addresses
    QString dohTemplate = QStringLiteral("https://cloudflare-dns.com/dns-query"); // Windows DoH template

    QString wgEndpoint;                           // host:port override for the WireGuard profile
    bool wgStripDns = true;                       // Linux: let the app handle DNS, not the profile
    bool manageSystemProxy = true;                // point the system proxy at SpoofDPI while it runs
    int networkTimeoutSec = 30;                   // connection timeout for downloads
    QString githubToken;                          // optional, avoids GitHub rate limits

    static Settings defaults();
    static Settings load();
    void save() const;
};

// Small JSON key/value store for internal state (installed tags, backups, flags).
class StateStore {
public:
    static bool has(const QString& key);
    static QJsonValue get(const QString& key);
    static QString str(const QString& key);
    static bool flag(const QString& key);
    static void set(const QString& key, const QJsonValue& value);
    static void remove(const QString& key);
};

} // namespace sdns

Q_DECLARE_METATYPE(sdns::Settings)
