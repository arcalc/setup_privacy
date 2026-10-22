#include "ToolsPage.h"

#include "core/Translator.h"

#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

namespace sdns {

QString ToolsPage::toolKey(int tool)
{
    switch (static_cast<Tool>(tool)) {
    case Tool::SpoofDpi: return QStringLiteral("spoofdpi");
    case Tool::Warp: return QStringLiteral("warp");
    case Tool::WireGuard: return QStringLiteral("wireguard");
    }
    return QString();
}

QString ToolsPage::actionKey(int action)
{
    switch (static_cast<ToolAction>(action)) {
    case ToolAction::Install: return QStringLiteral("install");
    case ToolAction::Start: return QStringLiteral("start");
    case ToolAction::Stop: return QStringLiteral("stop");
    case ToolAction::Enable: return QStringLiteral("enable");
    case ToolAction::Disable: return QStringLiteral("disable");
    case ToolAction::Uninstall: return QStringLiteral("uninstall");
    }
    return QString();
}

ToolsPage::ToolsPage(QWidget* parent) : QWidget(parent)
{
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    auto* content = new QWidget;
    auto* column = new QVBoxLayout(content);
    column->setSpacing(12);

    for (int tool = 0; tool < 3; ++tool) {
        Card& card = m_cards[tool];
        card.box = new QGroupBox;
        auto* layout = new QVBoxLayout(card.box);

        card.description = new QLabel;
        card.description->setWordWrap(true);
        card.description->setProperty("role", QStringLiteral("soft"));
        layout->addWidget(card.description);

        card.state = new QLabel;
        card.state->setProperty("role", QStringLiteral("heading"));
        layout->addWidget(card.state);

        auto* grid = new QGridLayout;
        for (int action = 0; action < 6; ++action) {
            card.buttons[action] = new QPushButton;
            grid->addWidget(card.buttons[action], action / 3, action % 3);
            connect(card.buttons[action], &QPushButton::clicked, this, [this, tool, action]() {
                emit actionRequested(tool, action);
            });
        }
        layout->addLayout(grid);
        column->addWidget(card.box);
    }
    column->addStretch(1);
    scroll->setWidget(content);
    outer->addWidget(scroll);

    retranslate();
    updateButtons();
}

void ToolsPage::retranslate()
{
    for (int tool = 0; tool < 3; ++tool) {
        const QString key = toolKey(tool);
        m_cards[tool].box->setTitle(T(QStringLiteral("tool.%1.name").arg(key)));
        m_cards[tool].description->setText(T(QStringLiteral("tool.%1.desc").arg(key)));
        for (int action = 0; action < 6; ++action) {
            const QString a = actionKey(action);
            m_cards[tool].buttons[action]->setText(T(QStringLiteral("action.%1").arg(a)));
            m_cards[tool].buttons[action]->setToolTip(T(QStringLiteral("action.%1.tip").arg(a)));
        }
        const ToolStatus& s = m_status[tool];
        QStringList parts;
        if (!s.installed) {
            parts << T(QStringLiteral("status.not_installed"));
        } else {
            parts << T(QStringLiteral("status.installed"));
            parts << T(s.running ? QStringLiteral("status.running") : QStringLiteral("status.stopped"));
            parts << T(s.enabled ? QStringLiteral("status.autostart_on") : QStringLiteral("status.autostart_off"));
        }
        m_cards[tool].state->setText(parts.join(QStringLiteral("  |  ")));
    }
}

void ToolsPage::setStatus(const StatusInfo& status)
{
    m_status[0] = status.spoof;
    m_status[1] = status.warp;
    m_status[2] = status.wireguard;
    retranslate();
    updateButtons();
}

void ToolsPage::setBusy(bool busy)
{
    m_busy = busy;
    updateButtons();
}

// Only the actions that make sense for the current state are enabled.
void ToolsPage::updateButtons()
{
    for (int tool = 0; tool < 3; ++tool) {
        const ToolStatus& s = m_status[tool];
        const bool enabledFor[6] = {
            !s.installed,                 // Install
            s.installed && !s.running,    // Start
            s.running,                    // Stop
            s.installed && !s.enabled,    // Enable
            s.installed && s.enabled,     // Disable
            s.installed                   // Uninstall
        };
        for (int action = 0; action < 6; ++action)
            m_cards[tool].buttons[action]->setEnabled(!m_busy && enabledFor[action]);
    }
}

} // namespace sdns
