#pragma once

#include "core/Engine.h"
#include "core/Settings.h"
#include "core/Types.h"

#include <QMainWindow>
#include <QMetaObject>
#include <QThread>

#include <utility>

class QCloseEvent;
class QGroupBox;
class QLabel;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QTabWidget;
class QTextBrowser;

namespace sdns {

class SettingsPage;
class ToolsPage;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(const Settings& settings, QWidget* parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void appendLog(const QString& line);
    void onBusyChanged(bool busy);
    void onStatus(const sdns::StatusInfo& status);
    void onSettingsChanged(const sdns::Settings& settings);
    void onToolAction(int tool, int action);
    void onSettingsSaved(const sdns::Settings& settings);
    void onSettingsReset();
    void startPreset(int mode);
    void toggleLanguage();
    void toggleTheme();

private:
    void buildUi();
    QWidget* buildDashboard();
    void retranslate();
    void applyTheme();
    void applyLanguage();
    void updateStatusLabels();
    QString aboutHtml() const;
    FixChoice showProblem(const Problem& problem);
    bool confirmTunnel();
    bool confirmYesNo(const QString& textKey);
    void pushSettingsToEngine();

    template <typename F>
    void callEngine(F&& function)
    {
        QMetaObject::invokeMethod(m_engine, std::forward<F>(function), Qt::QueuedConnection);
    }

    Settings m_settings;
    StatusInfo m_status;
    bool m_busy = false;

    QThread m_thread;
    Engine* m_engine = nullptr;

    QLabel* m_title = nullptr;
    QPushButton* m_languageButton = nullptr;
    QPushButton* m_themeButton = nullptr;
    QTabWidget* m_tabs = nullptr;
    QProgressBar* m_progress = nullptr;

    QGroupBox* m_statusBox = nullptr;
    QGroupBox* m_quickBox = nullptr;
    QGroupBox* m_actionsBox = nullptr;
    QLabel* m_quickHint = nullptr;
    QLabel* m_statusLabels[5] = {nullptr, nullptr, nullptr, nullptr, nullptr};
    QPushButton* m_modeButtons[3] = {nullptr, nullptr, nullptr};
    QLabel* m_modeDescs[3] = {nullptr, nullptr, nullptr};
    QPushButton* m_killButton = nullptr;
    QPushButton* m_restoreButton = nullptr;
    QPushButton* m_updateButton = nullptr;
    QPushButton* m_installButton = nullptr;
    QLabel* m_killDesc = nullptr;
    QLabel* m_restoreDesc = nullptr;
    QLabel* m_updateDesc = nullptr;
    QLabel* m_installDesc = nullptr;

    ToolsPage* m_toolsPage = nullptr;
    SettingsPage* m_settingsPage = nullptr;
    QPlainTextEdit* m_log = nullptr;
    QTextBrowser* m_about = nullptr;
};

} // namespace sdns
