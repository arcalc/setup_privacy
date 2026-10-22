#pragma once

#include "core/Settings.h"

#include <QList>
#include <QWidget>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

namespace sdns {

// The Advanced Settings panel. Every setting has a short explanation under it.
class SettingsPage : public QWidget {
    Q_OBJECT
public:
    explicit SettingsPage(QWidget* parent = nullptr);

    void load(const Settings& settings);
    void retranslate();
    void setBusy(bool busy);

signals:
    void saveRequested(const sdns::Settings& settings);
    void resetRequested();

private:
    struct Row {
        QString key;       // translation key prefix, e.g. "spoofPort"
        QLabel* label = nullptr;
        QLabel* help = nullptr;
    };

    QWidget* addRow(QLayout* form, const QString& key, QWidget* field);
    QWidget* addPathRow(QLayout* form, const QString& key, QLineEdit** edit);
    bool validate(QString* errorKey) const;
    Settings collect() const;

    Settings m_base;
    QList<Row> m_rows;

    QSpinBox* m_spoofPort = nullptr;
    QComboBox* m_argStyle = nullptr;
    QLineEdit* m_extraArgs = nullptr;
    QLineEdit* m_spoofPath = nullptr;
    QLineEdit* m_wgcfPath = nullptr;
    QLineEdit* m_wgQuickPath = nullptr;
    QLineEdit* m_warpCliPath = nullptr;
    QLineEdit* m_dnsServers = nullptr;
    QLineEdit* m_dohTemplate = nullptr;
    QLineEdit* m_wgEndpoint = nullptr;
    QCheckBox* m_wgStripDns = nullptr;
    QCheckBox* m_manageProxy = nullptr;
    QSpinBox* m_timeout = nullptr;
    QLineEdit* m_token = nullptr;
    QPushButton* m_save = nullptr;
    QPushButton* m_reset = nullptr;
    QList<QPushButton*> m_browseButtons;
};

} // namespace sdns
