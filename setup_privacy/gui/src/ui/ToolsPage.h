#pragma once

#include "core/Types.h"

#include <QWidget>

class QGroupBox;
class QLabel;
class QPushButton;

namespace sdns {

// The Advanced Tool Manager: one card per tool with a short explanation, its
// current state, and independent Install / Start / Stop / Enable / Disable /
// Uninstall buttons.
class ToolsPage : public QWidget {
    Q_OBJECT
public:
    explicit ToolsPage(QWidget* parent = nullptr);

    void retranslate();
    void setStatus(const StatusInfo& status);
    void setBusy(bool busy);

signals:
    void actionRequested(int tool, int action);

private:
    struct Card {
        QGroupBox* box = nullptr;
        QLabel* description = nullptr;
        QLabel* state = nullptr;
        QPushButton* buttons[6] = {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
    };

    void updateButtons();
    static QString toolKey(int tool);
    static QString actionKey(int action);

    Card m_cards[3];
    ToolStatus m_status[3];
    bool m_busy = false;
};

} // namespace sdns
