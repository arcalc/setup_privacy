#pragma once

#include <QString>
#include <QStringList>

namespace sdns::platform {

// True when the process has administrator (Windows) or root (Linux) rights.
bool isElevated();

// Starts a new elevated copy of this program (pkexec on Linux, UAC on Windows).
// Returns true when the elevated copy was launched; the caller should then quit.
bool relaunchElevated();

// Folder for settings, state, backups, downloaded tools, and logs.
QString dataDir();
QString binDir();
QString exeSuffix();

// Creates the data folder and, on Windows, limits it to Administrators and SYSTEM. Without this a
// standard user could pre-create the folder and plant a settings file that makes the elevated app
// run their program. Safe to call often; it only does the work once per run.
void ensureDataDir();

// Finds a program in PATH and in the usual system folders. Empty when missing.
QString findTool(const QString& name);

// "apt", "dnf", "pacman", "zypper", or an empty string.
QString packageManager();

// The package that provides a command, for the detected package manager.
QString packageFor(const QString& command);

// Windows Startup folder (empty on other systems).
QString startupFolder();

} // namespace sdns::platform
