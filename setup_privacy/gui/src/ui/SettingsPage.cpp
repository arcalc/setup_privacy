#include "SettingsPage.h"

#include "core/Translator.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QSpinBox>
#include <QVBoxLayout>

namespace sdns {

SettingsPage::SettingsPage(QWidget* parent) : QWidget(parent)
{
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    auto* content = new QWidget;
    auto* form = new QVBoxLayout(content);
    form->setSpacing(4);

    m_spoofPort = new QSpinBox;
    m_spoofPort->setRange(1, 65535);
    addRow(form, QStringLiteral("spoofPort"), m_spoofPort);

    m_argStyle = new QComboBox;
    m_argStyle->addItems({QStringLiteral("auto"), QStringLiteral("config"), QStringLiteral("flags"),
                          QStringLiteral("port"), QStringLiteral("none")});
    addRow(form, QStringLiteral("spoofArgStyle"), m_argStyle);

    m_extraArgs = new QLineEdit;
    addRow(form, QStringLiteral("spoofExtraArgs"), m_extraArgs);

    m_dnsServers = new QLineEdit;
    addRow(form, QStringLiteral("dnsServers"), m_dnsServers);

    m_dohTemplate = new QLineEdit;
    addRow(form, QStringLiteral("dohTemplate"), m_dohTemplate);

    m_wgEndpoint = new QLineEdit;
    addRow(form, QStringLiteral("wgEndpoint"), m_wgEndpoint);

    m_wgStripDns = new QCheckBox;
    addRow(form, QStringLiteral("wgStripDns"), m_wgStripDns);

    m_manageProxy = new QCheckBox;
    addRow(form, QStringLiteral("manageSystemProxy"), m_manageProxy);

    addPathRow(form, QStringLiteral("spoofPath"), &m_spoofPath);
    addPathRow(form, QStringLiteral("wgcfPath"), &m_wgcfPath);
    addPathRow(form, QStringLiteral("wgQuickPath"), &m_wgQuickPath);
    addPathRow(form, QStringLiteral("warpCliPath"), &m_warpCliPath);

    m_timeout = new QSpinBox;
    m_timeout->setRange(5, 300);
    m_timeout->setSuffix(QStringLiteral(" s"));
    addRow(form, QStringLiteral("networkTimeoutSec"), m_timeout);

    m_token = new QLineEdit;
    m_token->setEchoMode(QLineEdit::Password);
    addRow(form, QStringLiteral("githubToken"), m_token);

    form->addStretch(1);
    scroll->setWidget(content);
    outer->addWidget(scroll, 1);

    auto* buttons = new QHBoxLayout;
    buttons->addStretch(1);
    m_reset = new QPushButton;
    m_save = new QPushButton;
    buttons->addWidget(m_reset);
    buttons->addWidget(m_save);
    outer->addLayout(buttons);

    connect(m_reset, &QPushButton::clicked, this, &SettingsPage::resetRequested);
    connect(m_save, &QPushButton::clicked, this, [this]() {
        QString errorKey;
        if (!validate(&errorKey)) {
            QMessageBox::warning(this, T(QStringLiteral("settings.invalid_title")),
                                 T(QStringLiteral("settings.invalid_value"),
                                   {{QStringLiteral("name"), T(QStringLiteral("settings.%1.label").arg(errorKey))}}));
            return;
        }
        emit saveRequested(collect());
    });

    retranslate();
}

QWidget* SettingsPage::addRow(QLayout* form, const QString& key, QWidget* field)
{
    Row row;
    row.key = key;
    row.label = new QLabel;
    row.label->setProperty("role", QStringLiteral("heading"));
    row.help = new QLabel;
    row.help->setWordWrap(true);
    row.help->setProperty("role", QStringLiteral("soft"));
    m_rows.append(row);

    auto* box = new QVBoxLayout;
    box->setSpacing(2);
    box->addWidget(row.label);
    box->addWidget(field);
    box->addWidget(row.help);
    box->addSpacing(8);
    form->addItem(box);
    return field;
}

QWidget* SettingsPage::addPathRow(QLayout* form, const QString& key, QLineEdit** edit)
{
    auto* holder = new QWidget;
    auto* line = new QHBoxLayout(holder);
    line->setContentsMargins(0, 0, 0, 0);
    *edit = new QLineEdit;
    auto* browse = new QPushButton;
    m_browseButtons.append(browse);
    line->addWidget(*edit, 1);
    line->addWidget(browse);
    QLineEdit* target = *edit;
    connect(browse, &QPushButton::clicked, this, [this, target]() {
        const QString file = QFileDialog::getOpenFileName(this, T(QStringLiteral("settings.browse")));
        if (!file.isEmpty())
            target->setText(file);
    });
    return addRow(form, key, holder);
}

void SettingsPage::retranslate()
{
    for (const Row& row : m_rows) {
        row.label->setText(T(QStringLiteral("settings.%1.label").arg(row.key)));
        row.help->setText(T(QStringLiteral("settings.%1.help").arg(row.key)));
    }
    m_wgStripDns->setText(T(QStringLiteral("settings.wgStripDns.toggle")));
    m_manageProxy->setText(T(QStringLiteral("settings.manageSystemProxy.toggle")));
    for (QPushButton* b : m_browseButtons)
        b->setText(T(QStringLiteral("settings.browse")));
    m_save->setText(T(QStringLiteral("settings.save")));
    m_reset->setText(T(QStringLiteral("settings.reset")));
}

void SettingsPage::setBusy(bool busy)
{
    m_save->setEnabled(!busy);
    m_reset->setEnabled(!busy);
}

void SettingsPage::load(const Settings& s)
{
    m_base = s;
    m_spoofPort->setValue(s.spoofPort);
    m_argStyle->setCurrentText(s.spoofArgStyle);
    m_extraArgs->setText(s.spoofExtraArgs);
    m_spoofPath->setText(s.spoofPath);
    m_wgcfPath->setText(s.wgcfPath);
    m_wgQuickPath->setText(s.wgQuickPath);
    m_warpCliPath->setText(s.warpCliPath);
    m_dnsServers->setText(s.dnsServers.join(QLatin1Char(' ')));
    m_dohTemplate->setText(s.dohTemplate);
    m_wgEndpoint->setText(s.wgEndpoint);
    m_wgStripDns->setChecked(s.wgStripDns);
    m_manageProxy->setChecked(s.manageSystemProxy);
    m_timeout->setValue(s.networkTimeoutSec);
    m_token->setText(s.githubToken);
}

Settings SettingsPage::collect() const
{
    Settings s = m_base;   // keeps language and theme
    s.spoofPort = m_spoofPort->value();
    s.spoofArgStyle = m_argStyle->currentText();
    s.spoofExtraArgs = m_extraArgs->text().trimmed();
    s.spoofPath = m_spoofPath->text().trimmed();
    s.wgcfPath = m_wgcfPath->text().trimmed();
    s.wgQuickPath = m_wgQuickPath->text().trimmed();
    s.warpCliPath = m_warpCliPath->text().trimmed();
    s.dnsServers = m_dnsServers->text().simplified().split(QLatin1Char(' '), Qt::SkipEmptyParts);
    s.dohTemplate = m_dohTemplate->text().trimmed();
    s.wgEndpoint = m_wgEndpoint->text().trimmed();
    s.wgStripDns = m_wgStripDns->isChecked();
    s.manageSystemProxy = m_manageProxy->isChecked();
    s.networkTimeoutSec = m_timeout->value();
    s.githubToken = m_token->text().trimmed();
    return s;
}

// Returns false and the key of the first invalid field.
bool SettingsPage::validate(QString* errorKey) const
{
    const QStringList servers = m_dnsServers->text().simplified().split(QLatin1Char(' '), Qt::SkipEmptyParts);
    if (servers.isEmpty()) { *errorKey = QStringLiteral("dnsServers"); return false; }
    for (const QString& server : servers) {
        // "ip#hostname" pins a TLS name on Linux; only the address part is checked here.
        if (QHostAddress(server.section(QLatin1Char('#'), 0, 0)).isNull()) { *errorKey = QStringLiteral("dnsServers"); return false; }
    }
    if (!m_dohTemplate->text().trimmed().startsWith(QLatin1String("https://"))) { *errorKey = QStringLiteral("dohTemplate"); return false; }

    static const QRegularExpression endpoint(QStringLiteral("^[\\[\\]A-Za-z0-9._:-]+:\\d{1,5}$"));
    const QString ep = m_wgEndpoint->text().trimmed();
    if (!ep.isEmpty() && !endpoint.match(ep).hasMatch()) { *errorKey = QStringLiteral("wgEndpoint"); return false; }

    static const QRegularExpression shellChars(QStringLiteral("[;&|$`<>]"));
    if (shellChars.match(m_extraArgs->text()).hasMatch()) { *errorKey = QStringLiteral("spoofExtraArgs"); return false; }

    if (m_token->text().contains(QRegularExpression(QStringLiteral("\\s")))) { *errorKey = QStringLiteral("githubToken"); return false; }
    return true;
}

} // namespace sdns
