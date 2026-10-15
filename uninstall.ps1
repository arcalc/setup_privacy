#Requires -Version 5.1
<#
.SYNOPSIS
    Security DNS - Windows uninstaller.

.DESCRIPTION
    Restores the proxy registry values, per-adapter DNS settings, DoH server
    entries, and startup launcher captured by install.ps1. Then removes the
    SpoofDPI binary and the Security DNS data folder.

.EXAMPLE
    .\uninstall.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Configuration (must match install.ps1)
# -----------------------------------------------------------------------------
$DataRoot        = Join-Path $env:ProgramData 'SecurityDNS'
$BackupDir       = Join-Path $DataRoot 'backup'
$BackupFile      = Join-Path $BackupDir 'pre-install.json'
$StartupScript   = Join-Path ([Environment]::GetFolderPath('Startup')) 'security-dns.vbs'
$ProxyKey        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$CloudflareAddrs = @('1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001')

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------
function Write-Step([string]$Text)    { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Good([string]$Text)    { Write-Host "[+] $Text" -ForegroundColor Green }
function Write-Caution([string]$Text) { Write-Host "[!] $Text" -ForegroundColor Yellow }

# -----------------------------------------------------------------------------
# Privilege check
# -----------------------------------------------------------------------------
function Test-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw 'Security DNS uninstaller must run from an elevated PowerShell session.'
}

function Update-WinInet {
    if (-not ('SecurityDns.WinInet' -as [type])) {
        Add-Type -Namespace SecurityDns -Name WinInet -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
    }
    [void][SecurityDns.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][SecurityDns.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
}

# -----------------------------------------------------------------------------
# Restore functions
# -----------------------------------------------------------------------------
function Restore-ProxySettings($Proxy) {
    foreach ($name in @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL')) {
        $saved = $Proxy.$name
        if ($saved.Exists) {
            $type = 'String'
            if ($name -eq 'ProxyEnable') { $type = 'DWord' }
            Set-ItemProperty -Path $ProxyKey -Name $name -Value $saved.Value -Type $type
        } else {
            Remove-ItemProperty -Path $ProxyKey -Name $name -ErrorAction SilentlyContinue
        }
    }
    Update-WinInet
    Write-Good 'Proxy settings restored'
}

function Restore-DohSettings($State) {
    if (-not (Get-Command -Name Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        return
    }

    foreach ($address in $CloudflareAddrs) {
        Remove-DnsClientDohServerAddress -ServerAddress $address -ErrorAction SilentlyContinue
    }

    foreach ($entry in @($State.Doh)) {
        try {
            Add-DnsClientDohServerAddress -ServerAddress $entry.ServerAddress `
                -DohTemplate $entry.DohTemplate `
                -AllowFallbackToUdp ([bool]$entry.AllowFallbackToUdp) `
                -AutoUpgrade ([bool]$entry.AutoUpgrade)
        } catch {
            Write-Caution "Could not restore DoH entry for $($entry.ServerAddress): $($_.Exception.Message)"
        }
    }
    Write-Good 'DNS-over-HTTPS entries restored'
}

function Restore-DnsSettings($State) {
    foreach ($entry in @($State.Dns)) {
        $adapter = Get-NetAdapter -InterfaceIndex $entry.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $adapter) {
            Write-Caution "Adapter index $($entry.InterfaceIndex) no longer exists; skipped."
            continue
        }

        $servers = @($entry.Servers | Where-Object { $_ })
        if ($entry.Dhcp -or $servers.Count -eq 0) {
            Set-DnsClientServerAddress -InterfaceIndex $entry.InterfaceIndex -ResetServerAddresses
        } else {
            Set-DnsClientServerAddress -InterfaceIndex $entry.InterfaceIndex -ServerAddresses $servers
        }
        Write-Good "DNS restored on '$($adapter.Name)'"
    }
}

function Restore-StartupLauncher($State) {
    Remove-Item -LiteralPath $StartupScript -Force -ErrorAction SilentlyContinue
    $original = Join-Path $BackupDir 'security-dns.vbs.orig'
    if ($State.Startup.Existed -and (Test-Path -LiteralPath $original)) {
        Copy-Item -LiteralPath $original -Destination $StartupScript -Force
        Write-Good 'Original startup script restored'
    } else {
        Write-Good 'Startup launcher removed'
    }
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
function Invoke-Uninstall {
    Write-Step 'Stopping SpoofDPI'
    Get-Process -Name 'spoofdpi' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Good 'SpoofDPI stopped'

    if (-not (Test-Path -LiteralPath $BackupFile)) {
        Write-Caution "No backup found at $BackupFile. Network and proxy settings cannot be restored automatically."
        Remove-Item -LiteralPath $StartupScript -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $DataRoot -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    $state = Get-Content -LiteralPath $BackupFile -Raw | ConvertFrom-Json

    Write-Step 'Restoring the startup launcher'
    Restore-StartupLauncher -State $state

    Write-Step 'Restoring DNS-over-HTTPS'
    Restore-DohSettings -State $state

    Write-Step 'Restoring DNS settings'
    Restore-DnsSettings -State $state

    Write-Step 'Restoring the system proxy'
    Restore-ProxySettings -Proxy $state.Proxy

    Write-Step 'Cleaning up'
    Clear-DnsClientCache
    ipconfig /flushdns | Out-Null
    Remove-Item -LiteralPath $DataRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Good 'Security DNS binaries and backups removed'

    Write-Host ''
    Write-Good 'Your system has been returned to its previous state.'
    Write-Host 'Restart your browsers so they stop using the proxy.'
}

Invoke-Uninstall
