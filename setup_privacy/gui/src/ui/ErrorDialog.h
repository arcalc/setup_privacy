#pragma once

#include "core/Types.h"

#include <QDialog>

namespace sdns {

// Shows what went wrong and the proposed automatic fix, with Apply Fix / Cancel
// (and an alternative fix when one exists).
class ErrorDialog : public QDialog {
    Q_OBJECT
public:
    explicit ErrorDialog(const Problem& problem, QWidget* parent = nullptr);

    FixChoice choice() const { return m_choice; }

private:
    FixChoice m_choice = FixChoice::Cancel;
};

} // namespace sdns
