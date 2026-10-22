# Security DNS

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blue.svg)](#requirements)

**Security DNS** hides your DNS lookups from your Internet Service Provider (ISP), makes it harder for Deep Packet Inspection (DPI) equipment to read website names, and lets you control three privacy tools from one place: **SpoofDPI**, **Cloudflare WARP**, and **WireGuard (wgcf)**. It comes in two versions with the same features. It runs in English and Arabic.

Every change is backed up before it is made, and one button puts everything back.

---

## Download

| | **GUI version** | **CLI version** |
|---|---|---|
| For | Most people | Power users and servers |
| What it is | A desktop app (C++ / Qt6) for Windows and Linux | Bash (Linux) and PowerShell (Windows) scripts with a numbered menu |
| How you use it | Click buttons, read dialogs | Type a number in a menu, or run one command |
| Works over SSH | No | Yes |
| Size | A normal desktop app | A few small text files you can read |
| Get it | [**Download GUI Version**](https://github.com/arcalc/setup_privacy/releases/latest) or [build from source](#install-the-gui-version) | [**Download CLI Version**](#install-the-cli-version) |

Both versions offer the same tools, the same kill switch, the same settings, and the same smart error recovery.

> **Use one version at a time on a computer.** Both manage the same DNS and proxy settings. Switching is safe if you first press **Restore original settings** in the version you are leaving.

> **Project status.** The CLI and the GUI are new. The CLI error-recovery logic has automated tests; neither version has been verified on every Linux distribution or Windows build, and the GUI should be treated as a preview. Test on a spare machine first, and report bugs as normal issues. Report **security** problems privately (see [Security policy](#security-policy-and-contact)).

---

## Contents

- [The tools, explained](#the-tools-explained)
- [What each tool hides](#what-each-tool-hides)
- [Location and IP address trade-off](#location-and-ip-address-trade-off)
- [Advanced Tool Manager](#advanced-tool-manager)
- [Kill switch](#kill-switch)
- [Restore original settings](#restore-original-settings)
- [Smart error handling](#smart-error-handling)
- [Settings explained](#settings-explained)
- [Requirements](#requirements)
- [Install the GUI version](#install-the-gui-version)
- [Install the CLI version](#install-the-cli-version)
- [Browser settings](#browser-settings)
- [Verifying the setup](#verifying-the-setup)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)
- [Security policy and contact](#security-policy-and-contact)
- [License](#license)

---

## The tools, explained

| Tool | What it does | Public IP | Hides destination IPs from your ISP |
|---|---|---|---|
| **SpoofDPI** | A small proxy on your computer that splits the start of each HTTPS connection, so DPI equipment cannot read the website name in one packet. | Unchanged | No |
| **Cloudflare WARP** | The official Cloudflare client. All traffic goes through an encrypted tunnel to Cloudflare. | Changes | Yes |
| **WireGuard (wgcf)** | The same Cloudflare WARP tunnel, run by the standard WireGuard client with a profile made by the `wgcf` tool. | Changes | Yes |

**Encrypted DNS** is always part of the setup: DNS-over-TLS on Linux (`systemd-resolved`) and DNS-over-HTTPS on Windows. Plaintext fallback and DNS leaks to your router's resolver are blocked. On Windows builds older than 19041 (Windows 10 version 2004), system DoH is not available and the app tells you to enable Secure DNS in your browser instead.

**Quick modes** start one tool and stop the other two. Starting WARP and WireGuard together is blocked because both route all traffic.

---

## What each tool hides

No local tool can make your ISP completely blind.

| Information | SpoofDPI | WARP / WireGuard | Nothing running |
|---|---|---|---|
| DNS lookups (which domains you resolve) | Hidden | Hidden | Hidden |
| Website name in the TLS handshake (SNI) | Mostly hidden; fully hidden on sites that support ECH when ECH is on | Hidden inside the tunnel | Visible unless ECH is on |
| Destination IP addresses | **Visible** | **Hidden** (your ISP sees only Cloudflare) | **Visible** |
| Traffic volume and timing | Visible | Visible, as traffic to Cloudflare | Visible |
| Your public IP | Unchanged | Changes | Unchanged |
| Your apparent country | Unchanged | **May change** | Unchanged |

With WARP or WireGuard, Cloudflare can see your traffic instead of your ISP. The protection comes from trusting Cloudflare. Check the laws in your country before you use circumvention or privacy tools.

---

## Location and IP address trade-off

Hiding destination IPs from your ISP while keeping your apparent location is not possible with any tool here:

- A tunnel that hides destinations must send your traffic out from somewhere else.
- WARP exits from the Cloudflare data center nearest to you, which may be in another country. Websites that guess your location from your IP may then show that country.
- A VPN with an exit in your own country keeps your apparent location, but then the VPN provider sees your destinations instead of your ISP.

Both versions warn you and ask for confirmation before starting WARP or WireGuard. To check, compare your apparent country on an IP geolocation website with and without the tunnel.

---

## Advanced Tool Manager

Each tool can be controlled on its own. Both versions offer the same six actions per tool:

| Action | What it does |
|---|---|
| **Install** | Downloads and installs the tool. Nothing starts yet. |
| **Start** | Runs the tool now. It stops again when you stop it or restart, unless it is enabled. |
| **Stop** | Stops the tool now. Nothing is deleted. |
| **Enable** | Starts the tool automatically at boot or sign-in. |
| **Disable** | Does not start the tool automatically. |
| **Uninstall** | Stops the tool and deletes what this app installed for it. Programs that were already on your system before are left alone. |

- **GUI:** open the **Tool Manager** tab. Buttons that do not make sense in the current state are disabled.
- **CLI:** choose `4) Advanced Tool Manager` in the menu, then pick a tool.

SpoofDPI also sets the system proxy while it runs and clears it when it stops (you can turn that off in settings).

---

## Kill switch

**GUI:** the **KILL SWITCH** button on the Dashboard. **CLI:** menu option `9`, or `sudo security-dns --kill` (Linux) or `.\install.ps1 -Kill` (Windows).

It stops every proxy and tunnel at once, turns the system proxy off, and keeps encrypted DNS on. It does not ask questions and does not uninstall anything.

> It is an **emergency off switch**, not a firewall. If a tunnel drops by itself, traffic is not blocked automatically. Use a firewall if you need that.

---

## Restore original settings

**GUI:** the **Restore original settings** button. **CLI:** menu option `8`.

Before it changes anything for the first time, the app records your DNS, proxy, and related network settings. Restore stops all tools and puts those settings back exactly as they were. The app, the tools, and the backups stay installed, so you can switch everything on again at any time.

- **Linux** restores `/etc/resolv.conf`, the resolver configuration, `/etc/environment`, and each user's GNOME and KDE proxy settings.
- **Windows** restores per-adapter DNS (including DHCP), DNS-over-HTTPS entries, and the proxy registry values.

---

## Smart error handling

When something fails, the app does not just print an error. It follows the same steps in both versions:

1. **Detects** the failure from the error output or exit code.
2. **Explains** what went wrong and the proposed fix in plain language, with the technical details one click away.
3. **Asks** you to approve: **Apply Fix** (GUI button) or `a` (CLI).
4. **Applies** the fix automatically and **resumes** the operation.

If the same problem keeps happening, it stops after three attempts instead of looping.

| Problem | Automatic fix |
|---|---|
| Port already taken (for example 8080) | Picks a free port and saves it |
| SpoofDPI rejects its startup options | Switches to another option style and retries |
| `resolvconf` missing (WireGuard on Linux) | Installs `resolvconf` / `openresolv`, or lets the app handle DNS instead (recommended) |
| A needed program is missing | Installs it with your package manager (apt, dnf, pacman, zypper) |
| `systemd-resolved` missing | Installs and enables it |
| Network timeout | Waits, raises the timeout, retries |
| GitHub download rate limit | Waits 30 seconds and retries (a GitHub token avoids this) |
| Permission denied | Relaunches with administrator rights (GUI) or asks you to use `sudo` (CLI) |
| WARP and WireGuard started together | Stops the other tunnel first |
| No download for your system | Opens Settings so you can point to your own program |
| Download fails its SHA-256 check | Discards it and downloads again |
| Windows too old for system DoH | Continues without system DNS changes and tells you to use browser Secure DNS |

---

## Settings explained

Every setting has a short explanation next to it in the app. In the GUI they are in **Advanced Settings**. In the CLI they are in menu option `5`.

| Setting | What it does |
|---|---|
| SpoofDPI port | Port on this computer where SpoofDPI listens. Default 8080. If busy, a free port is chosen. |
| SpoofDPI argument style | How start options are passed to SpoofDPI: `auto` (reads the installed build's help), `config`, `flags`, `port`, or `none`. |
| SpoofDPI extra arguments | Added to the SpoofDPI command line. For advanced users. |
| DNS servers | Encrypted DNS servers for every lookup. Default: Cloudflare. On Linux, `ip#hostname` pins a TLS name. |
| DoH template (Windows) | The DNS-over-HTTPS address your DNS servers use. Must match your DNS servers. |
| WireGuard endpoint | Replaces the server address (`host:port`) in the WireGuard profile. Empty keeps the Cloudflare default. |
| WireGuard DNS handling (Linux) | On: the app handles DNS, so `resolvconf` is not needed. Off: the profile sets DNS itself. |
| System proxy | Point the system proxy at SpoofDPI while it runs. |
| Program paths | Use your own SpoofDPI, wgcf, wg-quick, or warp-cli instead of the managed copy. |
| Network timeout | Seconds to wait for a connection (5 to 300). |
| GitHub token | Optional. Avoids GitHub download rate limits. Stored only on this computer. |

---

## Requirements

**Linux:** x86_64 or arm64, systemd with `systemd-resolved`, root access (`sudo`, or `pkexec` for the GUI). WARP needs an apt-based (Debian, Ubuntu) or dnf-based (Fedora, RHEL family) system. The GUI also needs the Qt6 runtime and a TLS library (OpenSSL).

**Windows:** Windows 10 version 2004 (build 19041) or newer, including Windows 11, for system-wide DNS-over-HTTPS; an Administrator session. The CLI needs PowerShell 5.1 or newer.

**Both:** internet access to `api.github.com`, `github.com`, `raw.githubusercontent.com`, `1.1.1.1`, and for WARP `pkg.cloudflareclient.com` or `downloads.cloudflareclient.com`.

> **SpoofDPI on Windows:** the upstream project may not publish a Windows build. If no build is found, the app tells you and lets you point to a program you built yourself. WARP and WireGuard work without it.

---

## Install the GUI version

If a [release](https://github.com/arcalc/setup_privacy/releases/latest) is available, download it and run it. Otherwise build it from source.

**Linux build**

```bash
# Debian / Ubuntu
sudo apt install build-essential cmake qt6-base-dev policykit-1
# Fedora
sudo dnf install gcc-c++ cmake qt6-qtbase-devel polkit
# Arch
sudo pacman -S base-devel cmake qt6-base polkit

git clone https://github.com/arcalc/setup_privacy.git
cd setup_privacy
cmake -S gui -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build
security-dns
```

The app asks for administrator rights and relaunches itself through `pkexec`.

**Windows build:** install Qt 6 (6.4 or newer) and CMake, then from a Qt command prompt:

```bat
cmake -S gui -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
windeployqt build\Release\security-dns.exe
```

With MSVC, the program asks for administrator rights at launch (UAC).

In the app: use the **Dashboard** for quick modes, the kill switch, and restore; **Tool Manager** for per-tool actions; **Advanced Settings** for customization; **Log** for details; **About** for contact and security information. The **language** and **theme** buttons are at the top.

---

## Install the CLI version

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/arcalc/setup_privacy/main/cli/install.sh | sudo bash
```

It asks for your language, installs the `security-dns` command and an application-menu entry, backs up your settings, turns on encrypted DNS, and offers to start SpoofDPI. Open the menu later with:

```bash
sudo security-dns
```

Other options: `--kill` (kill switch), `--restore` (restore original settings), `--update`, `--uninstall`, `--version`.

### Windows

Open **PowerShell as Administrator**:

```powershell
irm https://raw.githubusercontent.com/arcalc/setup_privacy/main/cli/install.ps1 | iex
```

It installs to `C:\ProgramData\SecurityDNS` and creates **Security DNS** shortcuts in the Start Menu and on the Desktop. Parameters: `-Menu`, `-Kill`, `-Restore`, `-Update`, `-Uninstall`, `-Version`.

> Piping a remote script into a shell runs code you have not read. Download the file first, read it, then run it.

### The CLI menu

```text
  Security DNS v3.0.0

  Quick modes (start one tool and stop the others):
  1) SpoofDPI          keeps your public IP; bypasses DPI on this computer
  2) Cloudflare WARP   hides destination IPs from your ISP; changes your public IP
  3) WireGuard (wgcf)  the same WARP tunnel through WireGuard; changes your public IP

  Manage:
  4) Advanced Tool Manager  install, start, stop, enable, disable or remove each tool
  5) Settings               ports, DNS servers, WireGuard endpoint, tool paths
  6) Status
  7) Check for updates
  8) Restore original settings  undo DNS and proxy changes; keeps the app and tools
  9) KILL SWITCH  turn off every tool now; encrypted DNS stays on
  a) About, contact and security policy
  u) Uninstall everything
  q) Quit
```

To remove the CLI version completely, use `u` in the menu or run the uninstaller. It reverts only what it installed.

---

## Browser settings

Two browser settings add to the tools. Neither replaces them.

- **Enable ECH (Encrypted Client Hello).** It encrypts the website name in the TLS handshake, but only for sites that publish ECH keys, and the browser reads those keys through DNS, so it works best with the encrypted DNS here. Firefox: in `about:config`, set `network.dns.echconfig.enabled` and `network.dns.http3_echconfig.enabled` to `true`. Chromium browsers: enable `chrome://flags/#encrypted-client-hello`.
- **Disable QUIC / HTTP/3.** QUIC does not pass through an HTTP proxy, so it can bypass SpoofDPI. Firefox: set `network.http.http3.enable` to `false`. Chromium: disable `chrome://flags/#enable-quic`.

If your desktop is not detected, set the proxy by hand: `127.0.0.1`, your SpoofDPI port (default 8080), HTTP and HTTPS, exceptions `localhost, 127.0.0.0/8, ::1`.

---

## Verifying the setup

- Open **Status** (CLI option `6`) or the Dashboard (GUI).
- Linux DNS: `resolvectl status` should show `DNSOverTLS` and your DNS servers.
- Windows DNS: `Get-DnsClientDohServerAddress` should list your DNS servers.
- SpoofDPI proxy: `curl -I -x http://127.0.0.1:8080 https://example.com`.
- Location and IP: open an IP geolocation website with and without a tunnel and compare.
- Run a DNS leak test website. Only your chosen DNS servers should appear.

---

## Troubleshooting

**Something fails.** Read the dialog (GUI) or the prompt (CLI): it names the problem and the fix. Press **Apply Fix** or `a`. Details are in the **Log** tab (GUI) or in the terminal.

**SpoofDPI does not start.** The app runs a short test first and prints SpoofDPI's own output. If its options are not accepted, the argument style is switched automatically. You can also set it by hand in Settings.

**WARP or WireGuard changed my country.** This is the exit-location trade-off above. Stop the tunnel or use the kill switch.

**Websites fail in SpoofDPI mode.** If the proxy is down, apps that use the system proxy cannot connect. Press the kill switch or Stop for SpoofDPI.

**NetworkManager overrides DNS (Linux).** Make sure NetworkManager uses `systemd-resolved`.

**Arabic text looks garbled in Windows PowerShell.** Keep the UTF-8 byte-order mark in `install.ps1`.

**The GUI cannot get administrator rights (Linux).** Install `polkit` (provides `pkexec`), or start the app with `sudo`.

---

## Repository layout

```text
setup_privacy/
├── README.md        this file
├── SECURITY.md      how to report vulnerabilities (privately)
├── LICENSE          MIT
├── index.html       the website (GitHub Pages), English and Arabic
├── cli/
│   ├── install.sh       Linux CLI (installer and menu)
│   ├── uninstall.sh     Linux uninstaller and restore
│   ├── install.ps1      Windows CLI (installer and menu)
│   ├── uninstall.ps1    Windows uninstaller and restore
│   └── tests/run.sh     automated tests for the Linux CLI logic
└── gui/                 C++ / Qt6 application
    ├── CMakeLists.txt
    ├── resources/       English and Arabic texts
    ├── packaging/       Linux desktop entry
    └── src/
        ├── main.cpp
        ├── core/        tools, DNS, proxy, backups, recovery engine
        └── ui/          window, pages, dialogs, theme
```

---

## Security policy and contact

**Do NOT open public issues for security vulnerabilities.** Report them privately:

- Email: [thearcalc@protonmail.com](mailto:thearcalc@protonmail.com)
- GitHub: the **Security** tab, then **Report a vulnerability** (Private Vulnerability Reporting)

This protects the community until a fix is released. See [SECURITY.md](SECURITY.md) for details.

- **Developer portfolio:** https://arcalc.github.io/arcalc/
- **Support and security email:** thearcalc@protonmail.com

The same information is in the **About** screen of the GUI and the CLI, and in the footer of the website.

---

## License

This project is licensed under the [MIT License](LICENSE). SpoofDPI, wgcf, WireGuard, and the Cloudflare WARP client are developed by their own maintainers and are governed by their own licenses and terms.

**Disclaimer:** this software is provided "as is", without warranty of any kind. The authors are not responsible for misuse, legal consequences in your jurisdiction, loss of connectivity, or changes to your apparent location.
