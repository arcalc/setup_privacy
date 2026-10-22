#include "Translator.h"

#include <QFile>
#include <QJsonDocument>

namespace sdns {

namespace {

QJsonObject loadResource(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return QJsonDocument::fromJson(file.readAll()).object();
}

} // namespace

Translator::Translator()
    : m_english(loadResource(QStringLiteral(":/i18n/en.json"))),
      m_arabic(loadResource(QStringLiteral(":/i18n/ar.json")))
{
}

Translator& Translator::instance()
{
    static Translator translator;
    return translator;
}

void Translator::setLanguage(const QString& language)
{
    m_language = (language == QLatin1String("ar")) ? QStringLiteral("ar") : QStringLiteral("en");
}

QString Translator::tr(const QString& key, const QVariantMap& params) const
{
    QString text;
    if (m_language == QLatin1String("ar"))
        text = m_arabic.value(key).toString();
    if (text.isEmpty())
        text = m_english.value(key).toString();
    if (text.isEmpty())
        return key;
    for (auto it = params.constBegin(); it != params.constEnd(); ++it)
        text.replace(QLatin1Char('{') + it.key() + QLatin1Char('}'), it.value().toString());
    return text;
}

} // namespace sdns
