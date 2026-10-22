# Security Policy

Security DNS changes DNS, proxy, and network settings, so security reports are taken seriously.

## Do not report vulnerabilities in public

**Do NOT open a public issue, pull request, or discussion for a security vulnerability.**
Public reports put every user at risk before a fix exists.

Report it privately in one of these ways:

1. **Email:** [thearcalc@protonmail.com](mailto:thearcalc@protonmail.com)
2. **GitHub Private Vulnerability Reporting:** open the repository's **Security** tab, choose
   **Report a vulnerability**, and fill in the form.

Maintainer note: enable the second option under *Settings, Code security, Private vulnerability reporting*.

## What to include

- A clear description of the problem and its impact.
- The version (`security-dns --version` for the CLI, **About** tab for the GUI) and your operating system.
- Steps to reproduce, or a proof of concept.
- Whether you plan to disclose it, and when.

## What to expect

This is a volunteer project, so the following is a good-faith goal, not a guarantee:

- You will get an acknowledgment.
- The report is checked, and you are told whether it is accepted.
- A fix is prepared and released, and you are credited if you want to be.
- Details are published only after a fix is available.

## Scope

In scope: the CLI scripts (`cli/`), the GUI application (`gui/`), the installers' download and
verification logic, and anything that could expose user traffic or change system settings unexpectedly.

Out of scope: vulnerabilities in third-party tools (SpoofDPI, Cloudflare WARP, WireGuard, wgcf),
which should be reported to their own maintainers, and the privacy limits already documented in the
README (for example, destination IPs are visible to your ISP outside WARP and WireGuard modes).

## Contact

- Support and security email: thearcalc@protonmail.com
- Developer portfolio: https://arcalc.github.io/arcalc/
