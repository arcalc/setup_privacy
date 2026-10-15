# Security DNS

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blue.svg)](#requirements)

**Security DNS** hides your DNS lookups from your Internet Service Provider (ISP) and makes it harder for Deep Packet Inspection (DPI) equipment to read website names in your traffic. It installs [SpoofDPI](https://github.com/xvzc/SpoofDPI) as a local proxy, encrypts DNS queries, and configures your system automatically. Your public IP address is not changed.

Every change the installer makes is backed up first. The uninstaller restores those exact backups, so your system returns to its previous state.

---

## Table of Contents

- [How It Works](#how-it-works)
- [What Is and Is Not Hidden](#what-is-and-is-not-hidden)
- [Requirements](#requirements)
- [Installation](#installation)
- [Post-Installation](#post-installation)
- [Verifying the Setup](#verifying-the-setup)
- [Uninstalling and Reverting](#uninstalling-and-reverting)
- [Troubleshooting](#troubleshooting)
- [Project Files](#project-files)
- [Security Notes](#security-notes)
- [License](#license)

---

## How It Works

Security DNS combines two independent layers.

```text
 Browser / apps
      |
      |  (1) DNS lookups ----> systemd-resolved (Linux) or Windows DoH client
      |                            |  DNS-over-TLS / DNS-over-HTTPS
      |                            v
      |                        1.1.1.1 / 1.0.0.1  (encrypted, no plaintext fallback)
      |
      |  (2) Web traffic --> 127.0.0.1:8080 (or 8081) --> SpoofDPI --> destination server
                              splits the TLS ClientHello so DPI boxes
                              cannot read the hostname in a single packet
```

**Layer 1: Encrypted DNS**

- **Linux:** `systemd-resolved` uses DNS-over-TLS (DoT) with Cloudflare's resolvers `1.1.1.1` and `1.0.0.1`. `DNSOverTLS=yes` blocks plaintext fallback. `Domains=~.` routes every lookup through these resolvers, and `FallbackDNS=` is left empty, so queries do not leak to DHCP-supplied servers or hardcoded fallbacks.
- **Windows:** Cloudflare DNS-over-HTTPS (DoH) templates are registered and assigned to active physical adapters. `AllowFallbackToUdp` is disabled, so queries are never downgraded to plaintext.

**Layer 2: DPI bypass proxy**

SpoofDPI runs as a local HTTP/HTTPS proxy bound to `127.0.0.1` only. It fragments the TLS handshake so that DPI systems inspecting a single packet cannot read the Server Name Indication (SNI) field, which contains the website name. The proxy is not reachable from other machines.

The installers point your system proxy at the local SpoofDPI instance, so most applications route through it without further setup.

---

## What Is and Is Not Hidden

No local tool can make your ISP completely blind. This project does not claim otherwise.

| Information | Hidden from ISP? | Notes |
|---|---|---|
| DNS queries (which domains you look up) | **Yes** | Encrypted with DoT (Linux) or DoH (Windows). |
| Website name in the TLS handshake (SNI) | **Mostly** | Fragmentation defeats many DPI systems. Sites that support ECH are fully protected when ECH is enabled in your browser. |
| Destination IP addresses | **No** | Your ISP can still see which servers you connect to. |
| Traffic volume and timing | **No** | Visible to your ISP. |
| QUIC / HTTP/3 traffic (UDP 443) | **No, unless disabled** | Browsers may bypass the HTTP proxy with QUIC. Disable it as described below. |
| Apps that ignore system proxy settings | **No** | Some apps connect directly. |
| Apps with their own DNS or DoH settings | Depends | Those apps use their own resolver. |
| Traffic on other devices | **No** | This tool protects only the machine where it is installed. |

For stronger protection, for example against your ISP seeing destination IP addresses, combine this tool with a trusted VPN or the Tor Browser. Check the laws in your country regarding circumvention tools before you use them.

---

## Requirements

**Linux**
- x86_64 (amd64) architecture
- systemd with `systemd-resolved` (Ubuntu, Debian, Fedora, Arch, openSUSE, and most modern distributions)
- Root access through `sudo`
- Access to `api.github.com`, `github.com`, and `1.1.1.1`

**Windows**
- Windows 10 version 2004 (build 19041) or newer, including Windows 11, for system-wide DoH
- Windows PowerShell 5.1 or PowerShell 7
- An elevated (Administrator) PowerShell session

Older Windows builds are supported for the proxy, but system DNS is not changed on them. See [Troubleshooting](#troubleshooting).

---

## Installation

Both installers always fetch the latest SpoofDPI release from the GitHub API, so you never need to edit the scripts to update.

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/arcalc/setup_privacy/main/install.sh | sudo bash
```

The installer:

1. Installs missing dependencies (`curl`, `wget`, `tar`, `iproute2`, `ca-certificates`) with your package manager.
2. Backs up `resolved.conf`, `/etc/resolv.conf`, `/etc/environment`, and each desktop user's GNOME and KDE proxy settings.
3. Selects port `8080`, or `8081` if `8080` is busy.
4. Downloads the latest `linux-amd64` SpoofDPI release and verifies its SHA-256 checksum when one is published.
5. Creates and starts the `security-dns.service` systemd unit, which runs silently on boot.
6. Configures DNS-over-TLS through `systemd-resolved`.
7. Sets the proxy in environment variables, and in GNOME or KDE when detected.

**Uninstall or revert:**

```bash
curl -fsSL https://raw.githubusercontent.com/arcalc/setup_privacy/main/install.sh | sudo bash -s -- --uninstall
```

### Windows

Open **PowerShell as Administrator** and run:

```powershell
irm https://raw.githubusercontent.com/arcalc/setup_privacy/main/install.ps1 | iex
```

The installer:

1. Backs up the proxy registry values, per-adapter DNS settings, DoH server entries, and any existing startup launcher.
2. Stops any previous SpoofDPI instance and selects port `8080`, or `8081` if `8080` is busy.
3. Downloads the latest `windows-amd64` SpoofDPI release to `C:\ProgramData\SecurityDNS\bin` and verifies its checksum when one is published.
4. Creates a hidden launcher in your Startup folder, so the proxy starts silently at sign-in.
5. Registers Cloudflare DoH for `1.1.1.1`, `1.0.0.1`, and their IPv6 equivalents, and assigns them to active physical adapters.
6. Enables the system proxy at `127.0.0.1:<port>`.

**Uninstall or revert** (elevated PowerShell):

```powershell
$installer = "$env:TEMP\security-dns-install.ps1"
irm https://raw.githubusercontent.com/arcalc/setup_privacy/main/install.ps1 -OutFile $installer
& $installer -Uninstall
```

> **Security note:** Piping remote scripts into a shell runs code you have not read. Download the file first, review it, and then run it, especially on machines you care about.

---

## Post-Installation

1. **Restart your browser** so it picks up the new proxy and DNS settings.
2. **Log out and back in (Linux).** Environment proxy variables apply to new sessions.
3. **Enable ECH in your browser** (see below).
4. **Disable QUIC / HTTP/3 in your browser** (see below).
5. **Verify the setup** (see [Verifying the Setup](#verifying-the-setup)).

### System Proxy (Manual Fallback)

The installers configure the proxy automatically on Linux systems with GNOME or KDE, and on Windows. On other window managers, set it by hand:

- **Address:** `127.0.0.1`
- **Port:** `8080`, or `8081` if the installer reported that 8080 was busy
- **Protocols:** HTTP and HTTPS (both use the same address and port)
- **Exceptions:** `localhost, 127.0.0.0/8, ::1`

Where to find it:

- **GNOME:** Settings, Network, Network Proxy, Manual
- **KDE Plasma:** System Settings, Network, Proxy, Manual proxy configuration
- **Windows:** Settings, Network & Internet, Proxy, Manual proxy setup
- **Firefox (any OS):** Settings, Network Settings, Manual proxy configuration. "Use system proxy settings" also works.

### Enable ECH in Your Browser

**Encrypted Client Hello (ECH)** encrypts the Server Name Indication (SNI) field of the TLS handshake, which otherwise reveals the website name. ECH is a browser feature that complements the proxy. Two limits apply:

- ECH protects a connection only when the destination site publishes ECH keys. Sites without ECH are still covered by the proxy's fragmentation, which is weaker protection.
- The browser fetches ECH keys through DNS, so ECH works best together with the encrypted DNS configured by this tool.

**Firefox**

1. Open `about:config` and accept the warning.
2. Set `network.dns.echconfig.enabled` to `true`.
3. Set `network.dns.http3_echconfig.enabled` to `true`.

**Chrome, Edge, and other Chromium browsers**

1. Open `chrome://flags/#encrypted-client-hello` (or `edge://flags/` with the matching entry).
2. Set the option to **Enabled** if your version lists it, then restart the browser.

Option names change between browser versions. If you cannot find one, search the browser's flags page for "ECH" or "Encrypted Client Hello".

### Disable QUIC / HTTP/3

QUIC runs over UDP and does not pass through an HTTP proxy. If it stays enabled, traffic to sites that support it can bypass SpoofDPI and expose the hostname.

- **Firefox:** In `about:config`, set `network.http.http3.enable` to `false`.
- **Chromium:** Open `chrome://flags/#enable-quic` and set it to **Disabled**.

---

## Verifying the Setup

**Linux: proxy listening and service status**

```bash
ss -ltn | grep -E ':(8080|8081)\s'
systemctl status security-dns
```

**Windows: proxy listening**

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8080,8081 -ErrorAction SilentlyContinue
```

**Test the proxy directly (any OS with curl)**

```bash
curl -I -x http://127.0.0.1:8080 https://example.com
```

**Linux: DNS encryption**

```bash
resolvectl status
```

The global section should list `1.1.1.1` and `1.0.0.1` with DNS-over-TLS enabled.

**Windows: DNS encryption**

```powershell
Get-DnsClientDohServerAddress
```

You should see `1.1.1.1` and `1.0.0.1` with the Cloudflare DoH template.

For a broader check, run a DNS leak test website while the system is configured. Results should show only Cloudflare resolvers.

---

## Uninstalling and Reverting

Uninstalling restores the exact files and settings that existed before installation.

- **Linux:** Restores `resolved.conf`, the `/etc/resolv.conf` link or file, `/etc/environment`, and each user's GNOME and KDE proxy settings. Then it removes the service and binary.
- **Windows:** Restores per-adapter DNS (including DHCP-assigned DNS), DoH server entries, proxy registry values, and any previous startup launcher. Then it removes the hidden launcher and binary.

Settings changed after installation are overwritten by the saved backup. If a desktop user's GNOME settings cannot be restored because that user is not logged in, the uninstaller keeps its backups and reports the pending step. Log in as that user and run the uninstaller again.

---

## Troubleshooting

**Ports 8080 and 8081 are both busy.** Stop the application using them, then run the installer again. Installation stops if neither port is free.

**Windows reports that DoH is not supported.** Your build is older than 19041 (Windows 10 version 2004). The installer keeps your existing DNS to avoid sending plaintext queries to 1.1.1.1. Enable Secure DNS in your browser instead:

- **Chrome and Edge:** Settings, Privacy and security, Security, Use secure DNS, then choose Cloudflare or enter `https://cloudflare-dns.com/dns-query`.
- **Firefox:** Settings, Privacy & Security, DNS over HTTPS, then choose Max Protection or a custom provider.

**Websites fail after installation.** Check the service with `systemctl status security-dns` (Linux) or `Get-Process spoofdpi` (Windows). If the proxy is down, the browser cannot connect. Run the uninstaller to restore direct access, then reinstall.

**NetworkManager overrides DNS.** Make sure NetworkManager uses `systemd-resolved` (`dns=systemd-resolved`, the default on most distributions). Otherwise connection-specific DNS may bypass the encrypted configuration.

**VPN adapters.** The Windows installer changes only physical adapters. VPN adapters keep their own DNS settings.

---

## Project Files

| File | Purpose |
|---|---|
| `install.sh` | Linux installer, also handles `--uninstall` |
| `uninstall.sh` | Linux uninstaller, restores all backups |
| `install.ps1` | Windows installer, also handles `-Uninstall` |
| `uninstall.ps1` | Windows uninstaller, restores all backups |
| `index.html` | Project landing page (GitHub Pages) |
| `README.md` | This document |
| `LICENSE` | MIT License text |

---

## Security Notes

- The scripts store no credentials and send no personal data. Network requests go only to the GitHub API, GitHub release downloads, and the DNS resolvers you configured.
- SpoofDPI is bound to `127.0.0.1` and is not reachable from other machines.
- Downloads are verified with SHA-256 when the release publishes checksums. Otherwise the installer prints a warning.
- To avoid GitHub API rate limits, set `GITHUB_TOKEN` to a read-only personal access token before running the installer.
- Report security issues through GitHub's private vulnerability reporting, not as public issues.

---

## License

This project is licensed under the [MIT License](LICENSE). SpoofDPI is developed by its own maintainers and is governed by its own license.

## Disclaimer

This software is provided "as is", without warranty of any kind. The authors are not responsible for misuse, for legal consequences in your jurisdiction, or for loss of connectivity. Use it only in compliance with local laws.
