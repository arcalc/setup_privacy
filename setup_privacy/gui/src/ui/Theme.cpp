#include "Theme.h"

namespace sdns::theme {

namespace {

struct Palette {
    QString background;   // window background
    QString surface;      // inputs and cards
    QString text;         // primary text
    QString soft;         // secondary text and labels
    QString border;       // borders and dividers
    QString accent;       // buttons, selection, progress
};

Palette paletteFor(bool dark)
{
    if (dark)
        return {QStringLiteral("#121212"), QStringLiteral("#121212"), QStringLiteral("#E0E0E0"),
                QStringLiteral("#B0B0B0"), QStringLiteral("#444444"), QStringLiteral("#888888")};
    return {QStringLiteral("#FBF6DC"), QStringLiteral("#F3EBC8"), QStringLiteral("#8C6D1F"),
            QStringLiteral("#9C6B17"), QStringLiteral("#CDBE86"), QStringLiteral("#8C6D1F")};
}

} // namespace

QString styleSheet(bool dark)
{
    const Palette p = paletteFor(dark);
    QString css = QStringLiteral(R"QSS(
QWidget { background: %BG%; color: %TEXT%; font-size: 13px; }
QLabel { background: transparent; }
QLabel[role="soft"] { color: %SOFT%; }
QLabel[role="title"] { font-size: 20px; font-weight: 600; }
QLabel[role="heading"] { font-weight: 600; }
QPushButton { background: transparent; border: 1px solid %ACCENT%; border-radius: 6px; padding: 7px 14px; }
QPushButton:hover { background: %ACCENT%; color: %BG%; }
QPushButton:disabled { color: %SOFT%; border-color: %BORDER%; background: transparent; }
QPushButton#killButton { border: 2px solid %TEXT%; font-weight: 700; padding: 10px 16px; }
QPushButton#killButton:hover { background: %TEXT%; color: %BG%; }
QPushButton[flat="true"] { border: none; padding: 4px 8px; }
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextBrowser {
    background: %SURFACE%; border: 1px solid %BORDER%; border-radius: 6px; padding: 5px;
    selection-background-color: %ACCENT%; selection-color: %BG%; }
QComboBox QAbstractItemView { background: %SURFACE%; selection-background-color: %ACCENT%; selection-color: %BG%; }
QCheckBox { spacing: 8px; }
QGroupBox { border: 1px solid %BORDER%; border-radius: 8px; margin-top: 14px; padding: 12px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: %SOFT%; }
QTabWidget::pane { border: 1px solid %BORDER%; border-radius: 8px; top: -1px; }
QTabBar::tab { padding: 8px 16px; border: 1px solid %BORDER%; border-bottom: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px; color: %SOFT%; margin-right: 2px; }
QTabBar::tab:selected { color: %TEXT%; border-color: %ACCENT%; }
QProgressBar { border: 1px solid %BORDER%; border-radius: 4px; background: %SURFACE%; max-height: 6px; }
QProgressBar::chunk { background: %ACCENT%; }
QScrollArea { border: none; }
QScrollBar:vertical { background: %BG%; width: 10px; }
QScrollBar::handle:vertical { background: %BORDER%; border-radius: 5px; min-height: 24px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QToolTip { background: %SURFACE%; color: %TEXT%; border: 1px solid %BORDER%; padding: 4px; }
QMessageBox, QDialog { background: %BG%; }
)QSS");
    css.replace(QStringLiteral("%BG%"), p.background);
    css.replace(QStringLiteral("%SURFACE%"), p.surface);
    css.replace(QStringLiteral("%TEXT%"), p.text);
    css.replace(QStringLiteral("%SOFT%"), p.soft);
    css.replace(QStringLiteral("%BORDER%"), p.border);
    css.replace(QStringLiteral("%ACCENT%"), p.accent);
    return css;
}

QString linkColor(bool dark) { return paletteFor(dark).accent == QLatin1String("#888888") ? QStringLiteral("#E0E0E0") : QStringLiteral("#8C6D1F"); }

} // namespace sdns::theme
