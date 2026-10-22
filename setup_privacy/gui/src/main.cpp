#include "core/Platform.h"
#include "core/Settings.h"
#include "core/Translator.h"
#include "core/Types.h"
#include "ui/MainWindow.h"
#include "ui/Theme.h"

#include <QApplication>
#include <QMessageBox>
#include <QPushButton>

#ifndef APP_VERSION
#define APP_VERSION "3.0.0"
#endif

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Security DNS"));
    QApplication::setOrganizationName(QStringLiteral("arcalc"));
    QApplication::setApplicationVersion(QStringLiteral(APP_VERSION));

    // Types sent between the worker thread and the window through signals.
    qRegisterMetaType<sdns::StatusInfo>("sdns::StatusInfo");
    qRegisterMetaType<sdns::Settings>("sdns::Settings");

    const sdns::Settings settings = sdns::Settings::load();
    sdns::Translator::instance().setLanguage(settings.language);
    app.setLayoutDirection(sdns::Translator::instance().isRtl() ? Qt::RightToLeft : Qt::LeftToRight);
    app.setStyleSheet(sdns::theme::styleSheet(settings.theme == QLatin1String("dark")));

    // The app changes DNS, proxy, and network settings, which needs administrator rights.
    if (!sdns::platform::isElevated()) {
        QMessageBox box;
        box.setIcon(QMessageBox::Warning);
        box.setWindowTitle(sdns::T(QStringLiteral("elevation.title")));
        box.setText(sdns::T(QStringLiteral("elevation.text")));
        QPushButton* relaunch = box.addButton(sdns::T(QStringLiteral("elevation.relaunch")), QMessageBox::AcceptRole);
        box.addButton(sdns::T(QStringLiteral("elevation.continue")), QMessageBox::RejectRole);
        box.exec();
        if (box.clickedButton() == relaunch && sdns::platform::relaunchElevated())
            return 0;   // the elevated copy takes over
    }

    sdns::MainWindow window(settings);
    window.show();
    return app.exec();
}
