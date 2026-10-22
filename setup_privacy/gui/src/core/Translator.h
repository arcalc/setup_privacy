#pragma once

#include <QJsonObject>
#include <QString>
#include <QVariantMap>

namespace sdns {

// Looks up interface text by key. The texts live in resources/i18n/en.json and
// ar.json, so the C++ sources contain no translated strings.
class Translator {
public:
    static Translator& instance();

    void setLanguage(const QString& language);   // "en" or "ar"
    QString language() const { return m_language; }
    bool isRtl() const { return m_language == QLatin1String("ar"); }

    // Returns the text for a key; {name} placeholders are replaced from params.
    // Falls back to English, then to the key itself.
    QString tr(const QString& key, const QVariantMap& params = QVariantMap()) const;

private:
    Translator();

    QJsonObject m_english;
    QJsonObject m_arabic;
    QString m_language = QStringLiteral("en");
};

// Short helper for translated text.
inline QString T(const QString& key, const QVariantMap& params = QVariantMap())
{
    return Translator::instance().tr(key, params);
}

} // namespace sdns
