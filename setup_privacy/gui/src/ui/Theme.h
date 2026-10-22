#pragma once

#include <QString>

namespace sdns::theme {

// Dark : background #121212, text #E0E0E0, secondary #B0B0B0, borders #444444, accent #888888.
// Light: cream background with gold/amber text and accents.
QString styleSheet(bool dark);

// Color used for links in rich-text areas (About tab).
QString linkColor(bool dark);

} // namespace sdns::theme
