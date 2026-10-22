#include "ErrorDialog.h"

#include "core/Translator.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace sdns {

namespace {

QLabel* makeLabel(const QString& text, const char* role = nullptr)
{
    auto* label = new QLabel(text);
    label->setWordWrap(true);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    if (role)
        label->setProperty("role", QString::fromLatin1(role));
    return label;
}

} // namespace

ErrorDialog::ErrorDialog(const Problem& problem, QWidget* parent) : QDialog(parent)
{
    const QString key = problemKey(problem.kind);
    QVariantMap params = problem.params;
    for (const QString& name : {QStringLiteral("port"), QStringLiteral("tool"), QStringLiteral("other"), QStringLiteral("package")}) {
        if (!params.contains(name))
            params[name] = QString();
    }
    const QString prefix = QStringLiteral("problem.") + key + QLatin1Char('.');

    setWindowTitle(T(QStringLiteral("dialog.title")));
    setModal(true);
    setMinimumWidth(540);

    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(10);

    auto* title = makeLabel(T(prefix + QStringLiteral("title"), params), "title");
    layout->addWidget(title);

    layout->addWidget(makeLabel(T(QStringLiteral("dialog.what")), "heading"));
    layout->addWidget(makeLabel(T(prefix + QStringLiteral("explain"), params)));

    layout->addWidget(makeLabel(T(QStringLiteral("dialog.proposed")), "heading"));
    layout->addWidget(makeLabel(T(prefix + QStringLiteral("fix"), params)));

    auto* detailsButton = new QPushButton(T(QStringLiteral("dialog.show_details")));
    detailsButton->setProperty("flat", true);
    detailsButton->setCheckable(true);
    layout->addWidget(detailsButton, 0, Qt::AlignLeft);

    auto* details = new QPlainTextEdit(problem.detail.trimmed());
    details->setReadOnly(true);
    details->setMinimumHeight(120);
    details->setVisible(false);
    layout->addWidget(details);
    connect(detailsButton, &QPushButton::toggled, this, [detailsButton, details](bool shown) {
        details->setVisible(shown);
        detailsButton->setText(T(shown ? QStringLiteral("dialog.hide_details") : QStringLiteral("dialog.show_details")));
    });

    auto* buttons = new QHBoxLayout;
    buttons->addStretch(1);

    auto* apply = new QPushButton(T(QStringLiteral("dialog.apply")));
    apply->setDefault(true);
    connect(apply, &QPushButton::clicked, this, [this]() { m_choice = FixChoice::Primary; accept(); });

    if (problem.kind == ProblemKind::MissingResolvconf) {
        auto* alternate = new QPushButton(T(prefix + QStringLiteral("alt"), params));
        connect(alternate, &QPushButton::clicked, this, [this]() { m_choice = FixChoice::Alternate; accept(); });
        buttons->addWidget(alternate);
    }

    auto* cancel = new QPushButton(T(QStringLiteral("dialog.cancel")));
    connect(cancel, &QPushButton::clicked, this, [this]() { m_choice = FixChoice::Cancel; reject(); });

    buttons->addWidget(cancel);
    buttons->addWidget(apply);
    layout->addLayout(buttons);
}

} // namespace sdns
