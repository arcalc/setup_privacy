#include "MainWindow.h"

#include "ErrorDialog.h"
#include "SettingsPage.h"
#include "Theme.h"
#include "ToolsPage.h"
#include "core/Translator.h"

#include <QApplication>
#include <QCloseEvent>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QTabWidget>
#include <QTextBrowser>
#include <QVBoxLayout>

#ifndef APP_VERSION
#define APP_VERSION "3.0.0"
#endif

namespace sdns {

namespace {

constexpr const char* kPortfolioUrl = "https://arcalc.github.io/arcalc/";
constexpr const char* kContactEmail = "thearcalc@protonmail.com";

QLabel* softLabel()
{
    auto* label = new QLabel;
    label->setWordWrap(true);
    label->setProperty("role", QStringLiteral("soft"));
    return label;
}

} // namespace

MainWindow::MainWindow(const Settings& settings, QWidget* parent) : QMainWindow(parent), m_settings(settings)
{
    buildUi();

    // All long work runs in one worker thread so the window never freezes.
    m_engine = new Engine(m_settings);
    m_engine->moveToThread(&m_thread);
    connect(&m_thread, &QThread::finished, m_engine, &QObject::deleteLater);

    m_engine->setProblemHandler([this](const Problem& problem) {
        FixChoice choice = FixChoice::Cancel;
        // The worker waits here until the user answers the dialog in the main thread.
        QMetaObject::invokeMethod(this, [this, &problem, &choice]() { choice = showProblem(problem); },
                                  Qt::BlockingQueuedConnection);
        return choice;
    });

    connect(m_engine, &Engine::logLine, this, &MainWindow::appendLog);
    connect(m_engine, &Engine::busyChanged, this, &MainWindow::onBusyChanged);
    connect(m_engine, &Engine::statusReady, this, &MainWindow::onStatus);
    connect(m_engine, &Engine::settingsChanged, this, &MainWindow::onSettingsChanged);
    connect(m_engine, &Engine::openSettingsRequested, this, [this]() { m_tabs->setCurrentWidget(m_settingsPage); });
    connect(m_engine, &Engine::relaunchRequested, qApp, &QApplication::quit);

    applyLanguage();
    applyTheme();

    m_thread.start();
    callEngine([this]() { m_engine->refreshStatus(); });
}

MainWindow::~MainWindow()
{
    m_thread.quit();
    m_thread.wait(5000);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (m_busy) {
        appendLog(T(QStringLiteral("log.wait_before_close")));
        event->ignore();
        return;
    }
    event->accept();
}

// -----------------------------------------------------------------------------
// UI construction
// -----------------------------------------------------------------------------
void MainWindow::buildUi()
{
    setMinimumSize(780, 640);
    auto* central = new QWidget;
    auto* root = new QVBoxLayout(central);

    auto* header = new QHBoxLayout;
    m_title = new QLabel;
    m_title->setProperty("role", QStringLiteral("title"));
    m_languageButton = new QPushButton;
    m_themeButton = new QPushButton;
    header->addWidget(m_title);
    header->addStretch(1);
    header->addWidget(m_languageButton);
    header->addWidget(m_themeButton);
    root->addLayout(header);

    m_tabs = new QTabWidget;
    m_toolsPage = new ToolsPage;
    m_settingsPage = new SettingsPage;
    m_settingsPage->load(m_settings);

    m_log = new QPlainTextEdit;
    m_log->setReadOnly(true);
    m_log->setMaximumBlockCount(5000);

    m_about = new QTextBrowser;
    m_about->setOpenExternalLinks(true);

    m_tabs->addTab(buildDashboard(), QString());
    m_tabs->addTab(m_toolsPage, QString());
    m_tabs->addTab(m_settingsPage, QString());
    m_tabs->addTab(m_log, QString());
    m_tabs->addTab(m_about, QString());
    root->addWidget(m_tabs, 1);

    m_progress = new QProgressBar;
    m_progress->setRange(0, 0);       // indeterminate while a task runs
    m_progress->setTextVisible(false);
    m_progress->setVisible(false);
    root->addWidget(m_progress);

    setCentralWidget(central);

    connect(m_languageButton, &QPushButton::clicked, this, &MainWindow::toggleLanguage);
    connect(m_themeButton, &QPushButton::clicked, this, &MainWindow::toggleTheme);
    connect(m_toolsPage, &ToolsPage::actionRequested, this, &MainWindow::onToolAction);
    connect(m_settingsPage, &SettingsPage::saveRequested, this, &MainWindow::onSettingsSaved);
    connect(m_settingsPage, &SettingsPage::resetRequested, this, &MainWindow::onSettingsReset);
}

QWidget* MainWindow::buildDashboard()
{
    auto* page = new QWidget;
    auto* layout = new QVBoxLayout(page);
    layout->setSpacing(12);

    // Status
    m_statusBox = new QGroupBox;
    auto* statusLayout = new QVBoxLayout(m_statusBox);
    for (QLabel*& label : m_statusLabels) {
        label = new QLabel;
        statusLayout->addWidget(label);
    }
    layout->addWidget(m_statusBox);

    // Quick modes
    m_quickBox = new QGroupBox;
    auto* quickLayout = new QVBoxLayout(m_quickBox);
    m_quickHint = softLabel();
    quickLayout->addWidget(m_quickHint);
    for (int i = 0; i < 3; ++i) {
        m_modeButtons[i] = new QPushButton;
        m_modeDescs[i] = softLabel();
        quickLayout->addWidget(m_modeButtons[i]);
        quickLayout->addWidget(m_modeDescs[i]);
        connect(m_modeButtons[i], &QPushButton::clicked, this, [this, i]() { startPreset(i + 1); });
    }
    layout->addWidget(m_quickBox);

    // Kill switch, restore, updates, dependencies
    m_actionsBox = new QGroupBox;
    auto* actions = new QVBoxLayout(m_actionsBox);

    m_killButton = new QPushButton;
    m_killButton->setObjectName(QStringLiteral("killButton"));
    m_killDesc = softLabel();
    m_restoreButton = new QPushButton;
    m_restoreDesc = softLabel();
    m_updateButton = new QPushButton;
    m_updateDesc = softLabel();
    m_installButton = new QPushButton;
    m_installDesc = softLabel();

    actions->addWidget(m_killButton);
    actions->addWidget(m_killDesc);
    actions->addWidget(m_restoreButton);
    actions->addWidget(m_restoreDesc);
    actions->addWidget(m_installButton);
    actions->addWidget(m_installDesc);
    actions->addWidget(m_updateButton);
    actions->addWidget(m_updateDesc);
    layout->addWidget(m_actionsBox);
    layout->addStretch(1);

    // Kill switch is instant: no confirmation, no recovery dialogs.
    connect(m_killButton, &QPushButton::clicked, this, [this]() { callEngine([this]() { m_engine->killSwitch(); }); });
    connect(m_restoreButton, &QPushButton::clicked, this, [this]() {
        if (confirmYesNo(QStringLiteral("confirm.restore")))
            callEngine([this]() { m_engine->restoreOriginal(); });
    });
    connect(m_installButton, &QPushButton::clicked, this, [this]() { callEngine([this]() { m_engine->installMissing(); }); });
    connect(m_updateButton, &QPushButton::clicked, this, [this]() { callEngine([this]() { m_engine->updateTools(); }); });
    return page;
}

// -----------------------------------------------------------------------------
// Language, theme, text
// -----------------------------------------------------------------------------
void MainWindow::applyLanguage()
{
    Translator::instance().setLanguage(m_settings.language);
    qApp->setLayoutDirection(Translator::instance().isRtl() ? Qt::RightToLeft : Qt::LeftToRight);
    retranslate();
}

void MainWindow::applyTheme()
{
    qApp->setStyleSheet(theme::styleSheet(m_settings.theme == QLatin1String("dark")));
    retranslate();   // the About page embeds theme colors
}

void MainWindow::retranslate()
{
    setWindowTitle(T(QStringLiteral("app.title")));
    m_title->setText(T(QStringLiteral("app.title")));
    m_languageButton->setText(T(QStringLiteral("lang.switch_to")));
    m_themeButton->setText(T(m_settings.theme == QLatin1String("dark") ? QStringLiteral("theme.to_light") : QStringLiteral("theme.to_dark")));

    m_tabs->setTabText(0, T(QStringLiteral("tab.dashboard")));
    m_tabs->setTabText(1, T(QStringLiteral("tab.tools")));
    m_tabs->setTabText(2, T(QStringLiteral("tab.settings")));
    m_tabs->setTabText(3, T(QStringLiteral("tab.log")));
    m_tabs->setTabText(4, T(QStringLiteral("tab.about")));

    m_statusBox->setTitle(T(QStringLiteral("dash.status")));
    m_quickBox->setTitle(T(QStringLiteral("dash.quick")));
    m_actionsBox->setTitle(T(QStringLiteral("dash.actions")));
    m_quickHint->setText(T(QStringLiteral("dash.quick.hint")));

    const char* modeKeys[3] = {"spoofdpi", "warp", "wireguard"};
    for (int i = 0; i < 3; ++i) {
        const QString key = QString::fromLatin1(modeKeys[i]);
        m_modeButtons[i]->setText(T(QStringLiteral("mode.%1").arg(key)));
        m_modeDescs[i]->setText(T(QStringLiteral("mode.%1.desc").arg(key)));
    }
    m_killButton->setText(T(QStringLiteral("dash.kill")));
    m_killDesc->setText(T(QStringLiteral("dash.kill.desc")));
    m_restoreButton->setText(T(QStringLiteral("dash.restore")));
    m_restoreDesc->setText(T(QStringLiteral("dash.restore.desc")));
    m_installButton->setText(T(QStringLiteral("dash.install_missing")));
    m_installDesc->setText(T(QStringLiteral("dash.install_missing.desc")));
    m_updateButton->setText(T(QStringLiteral("dash.update")));
    m_updateDesc->setText(T(QStringLiteral("dash.update.desc")));

    m_toolsPage->retranslate();
    m_settingsPage->retranslate();
    m_about->setHtml(aboutHtml());
    updateStatusLabels();
}

QString MainWindow::aboutHtml() const
{
    const QString link = theme::linkColor(m_settings.theme == QLatin1String("dark"));
    const QString portfolio = QString::fromLatin1(kPortfolioUrl);
    const QString email = QString::fromLatin1(kContactEmail);
    const QString dir = Translator::instance().isRtl() ? QStringLiteral(" dir=\"rtl\"") : QString();

    QString html;
    html += QStringLiteral("<div") + dir + QStringLiteral(">");
    html += QStringLiteral("<h2>") + T(QStringLiteral("app.title")) + QStringLiteral("</h2>");
    html += QStringLiteral("<p>") + T(QStringLiteral("about.version"), {{QStringLiteral("version"), QString::fromLatin1(APP_VERSION)}}) + QStringLiteral("</p>");
    html += QStringLiteral("<p><b>") + T(QStringLiteral("about.developer")) + QStringLiteral("</b><br><a style=\"color:") + link
            + QStringLiteral("\" href=\"") + portfolio + QStringLiteral("\">") + portfolio + QStringLiteral("</a></p>");
    html += QStringLiteral("<p><b>") + T(QStringLiteral("about.contact")) + QStringLiteral("</b><br><a style=\"color:") + link
            + QStringLiteral("\" href=\"mailto:") + email + QStringLiteral("\">") + email + QStringLiteral("</a></p>");
    html += QStringLiteral("<h3>") + T(QStringLiteral("about.security_title")) + QStringLiteral("</h3>");
    html += QStringLiteral("<p>") + T(QStringLiteral("about.security_text"), {{QStringLiteral("email"), email}}) + QStringLiteral("</p>");
    html += QStringLiteral("<p>") + T(QStringLiteral("about.single_version")) + QStringLiteral("</p>");
    html += QStringLiteral("<p>") + T(QStringLiteral("about.license")) + QStringLiteral("</p></div>");
    return html;
}

void MainWindow::updateStatusLabels()
{
    auto tool = [](const QString& nameKey, const ToolStatus& s, const QString& extra) {
        QString text = T(nameKey) + QStringLiteral(": ");
        if (!s.installed)
            return text + T(QStringLiteral("status.not_installed"));
        text += T(s.running ? QStringLiteral("status.running") : QStringLiteral("status.stopped"));
        text += QStringLiteral(", ") + T(s.enabled ? QStringLiteral("status.autostart_on") : QStringLiteral("status.autostart_off"));
        return text + extra;
    };
    m_statusLabels[0]->setText(tool(QStringLiteral("tool.spoofdpi.name"), m_status.spoof,
                                    QStringLiteral(" (%1)").arg(T(QStringLiteral("status.port"), {{QStringLiteral("port"), m_status.spoofPort}}))));
    m_statusLabels[1]->setText(tool(QStringLiteral("tool.warp.name"), m_status.warp, QString()));
    m_statusLabels[2]->setText(tool(QStringLiteral("tool.wireguard.name"), m_status.wireguard, QString()));
    m_statusLabels[3]->setText(T(QStringLiteral("status.dns")) + QStringLiteral(": ")
                               + T(m_status.dnsEncrypted ? QStringLiteral("status.dns_on") : QStringLiteral("status.dns_off")));
    m_statusLabels[4]->setText(T(QStringLiteral("status.privileges")) + QStringLiteral(": ")
                               + T(m_status.elevated ? QStringLiteral("status.admin_yes") : QStringLiteral("status.admin_no")));
}

// -----------------------------------------------------------------------------
// Engine events
// -----------------------------------------------------------------------------
void MainWindow::appendLog(const QString& line)
{
    if (!line.trimmed().isEmpty())
        m_log->appendPlainText(line);
}

void MainWindow::onBusyChanged(bool busy)
{
    m_busy = busy;
    m_progress->setVisible(busy);
    for (QPushButton* b : {m_modeButtons[0], m_modeButtons[1], m_modeButtons[2], m_restoreButton, m_updateButton, m_installButton})
        b->setEnabled(!busy);
    // The kill switch stays available while a task runs: it is the emergency stop.
    m_languageButton->setEnabled(!busy);
    m_toolsPage->setBusy(busy);
    m_settingsPage->setBusy(busy);
}

void MainWindow::onStatus(const StatusInfo& status)
{
    m_status = status;
    m_toolsPage->setStatus(status);
    updateStatusLabels();
}

void MainWindow::onSettingsChanged(const Settings& settings)
{
    // The engine changed a setting on its own (for example a new free port).
    m_settings = settings;
    m_settingsPage->load(m_settings);
}

FixChoice MainWindow::showProblem(const Problem& problem)
{
    ErrorDialog dialog(problem, this);
    dialog.exec();
    return dialog.choice();
}

// -----------------------------------------------------------------------------
// User actions
// -----------------------------------------------------------------------------
bool MainWindow::confirmYesNo(const QString& textKey)
{
    QMessageBox box(this);
    box.setIcon(QMessageBox::Question);
    box.setText(T(textKey));
    QPushButton* yes = box.addButton(T(QStringLiteral("btn.continue")), QMessageBox::AcceptRole);
    box.addButton(T(QStringLiteral("btn.cancel")), QMessageBox::RejectRole);
    box.exec();
    return box.clickedButton() == yes;
}

bool MainWindow::confirmTunnel() { return confirmYesNo(QStringLiteral("confirm.tunnel")); }

void MainWindow::startPreset(int mode)
{
    if (mode != 1 && !confirmTunnel())
        return;
    callEngine([this, mode]() { m_engine->applyPreset(mode); });
}

void MainWindow::onToolAction(int tool, int action)
{
    const Tool t = static_cast<Tool>(tool);
    const ToolAction a = static_cast<ToolAction>(action);
    if (a == ToolAction::Start && t != Tool::SpoofDpi && !confirmTunnel())
        return;
    if (a == ToolAction::Uninstall && !confirmYesNo(QStringLiteral("confirm.uninstall")))
        return;
    callEngine([this, tool, action]() { m_engine->performToolAction(tool, action); });
}

void MainWindow::pushSettingsToEngine()
{
    const Settings copy = m_settings;
    callEngine([this, copy]() { m_engine->updateSettings(copy); });
}

void MainWindow::onSettingsSaved(const Settings& settings)
{
    m_settings = settings;
    pushSettingsToEngine();
    appendLog(T(QStringLiteral("log.settings_saved")));
}

void MainWindow::onSettingsReset()
{
    Settings defaults = Settings::defaults();
    defaults.language = m_settings.language;
    defaults.theme = m_settings.theme;
    m_settings = defaults;
    m_settingsPage->load(m_settings);
    pushSettingsToEngine();
    appendLog(T(QStringLiteral("log.settings_reset")));
}

void MainWindow::toggleLanguage()
{
    m_settings.language = (m_settings.language == QLatin1String("en")) ? QStringLiteral("ar") : QStringLiteral("en");
    applyLanguage();
    pushSettingsToEngine();
}

void MainWindow::toggleTheme()
{
    m_settings.theme = (m_settings.theme == QLatin1String("dark")) ? QStringLiteral("light") : QStringLiteral("dark");
    applyTheme();
    pushSettingsToEngine();
}

} // namespace sdns
