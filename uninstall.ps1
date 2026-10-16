#Requires -Version 5.1
<#
.SYNOPSIS
    Security DNS - Windows uninstaller.

.DESCRIPTION
    Two modes:
      -RestoreOnly  Reverts DNS, DNS-over-HTTPS, proxy, and startup settings to the
                    original backups and stops all tunnels. The application, the
                    dependencies, the shortcuts, and the backups stay in place.
      (default)     Full uninstall. Reverts the same settings, removes WARP and
                    WireGuard only if install.ps1 installed them, removes the
                    shortcuts, and deletes the application folder.

.PARAMETER RestoreOnly
    Restore original settings without uninstalling.

.EXAMPLE
    .\uninstall.ps1

.EXAMPLE
    .\uninstall.ps1 -RestoreOnly
#>
[CmdletBinding()]
param(
    [switch]$RestoreOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Configuration (must match install.ps1)
# -----------------------------------------------------------------------------
$AppDir          = Join-Path $env:ProgramData 'SecurityDNS'
$BackupDir       = Join-Path $AppDir 'backup'
$BackupFile      = Join-Path $BackupDir 'pre-install.json'
$StateFile       = Join-Path $AppDir 'state.json'
$WgTunnelName    = 'security-dns'
$WgExe           = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
$WarpCli         = Join-Path $env:ProgramFiles 'Cloudflare\Cloudflare WARP\warp-cli.exe'
$StartupScript   = Join-Path ([Environment]::GetFolderPath('Startup')) 'security-dns.vbs'
$ProxyKey        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$CloudflareAddrs = @('1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001')

# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------
function Write-Step([string]$Text)    { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Good([string]$Text)    { Write-Host "[+] $Text" -ForegroundColor Green }
function Write-Caution([string]$Text) { Write-Host "[!] $Text" -ForegroundColor Yellow }

function Test-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw 'The Security DNS uninstaller must run from an elevated PowerShell session.'
}

# -----------------------------------------------------------------------------
# State and registry helpers
# -----------------------------------------------------------------------------
function Read-State {
    if (Test-Path -LiteralPath $StateFile) {
        return (Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json)
    }
    return [pscustomobject]@{}
}

function Get-StateValue([string]$Key) {
    $state = Read-State
    $prop = $state.PSObject.Properties[$Key]
    if ($prop) { return $prop.Value }
    return $null
}

function Set-StateValue([string]$Key, $Value) {
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
    $state = Read-State
    $table = [ordered]@{}
    foreach ($prop in $state.PSObject.Properties) { $table[$prop.Name] = $prop.Value }
    $table[$Key] = $Value
    $table | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StateFile -Encoding UTF8
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
# Stop everything first
# -----------------------------------------------------------------------------
function Stop-AllRouting {
    Write-Step 'Stopping SpoofDPI, WireGuard, and WARP'
    Get-Process -Name 'spoofdpi' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $WgExe) {
        & $WgExe /uninstalltunnelservice $WgTunnelName *> $null
    }

    if (Test-Path -LiteralPath $WarpCli) {
        & $WarpCli --accept-tos disconnect *> $null
    }
    Write-Good 'Proxy, tunnels, and WARP connection stopped'
}

# -----------------------------------------------------------------------------
# Restore functions (exact values from the pre-install backup)
# -----------------------------------------------------------------------------
function Restore-StartupLauncher {
    Remove-Item -LiteralPath $StartupScript -Force -ErrorAction SilentlyContinue
    $original = Join-Path $BackupDir 'security-dns.vbs.orig'
    if (Test-Path -LiteralPath $BackupFile) {
        $backup = Get-Content -LiteralPath $BackupFile -Raw | ConvertFrom-Json
        if ($backup.Startup.Existed -and (Test-Path -LiteralPath $original)) {
            Copy-Item -LiteralPath $original -Destination $StartupScript -Force
            Write-Good 'Original startup script restored'
            return
        }
    }
    Write-Good 'Startup launcher removed'
}

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

function Restore-DohSettings($Backup) {
    if (-not (Get-Command -Name Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        return
    }

    foreach ($address in $CloudflareAddrs) {
        Remove-DnsClientDohServerAddress -ServerAddress $address -ErrorAction SilentlyContinue
    }

    foreach ($entry in @($Backup.Doh)) {
        try {
            Add-DnsClientDohServerAddress -ServerAddress $entry.ServerAddress `
                -DohTemplate $entry.DohTemplate `
                -AllowFallbackToUdp ([bool]$entry.AllowFallbackToUdp) `
                -AutoUpgrade ([bool]$entry.AutoUpgrade) | Out-Null
        } catch {
            Write-Caution "Could not restore DoH entry for $($entry.ServerAddress): $($_.Exception.Message)"
        }
    }
    Write-Good 'DNS-over-HTTPS entries restored'
}

function Restore-DnsSettings($Backup) {
    foreach ($entry in @($Backup.Dns)) {
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
    Clear-DnsClientCache
}

function Restore-AllNetworkSettings {
    if (-not (Test-Path -LiteralPath $BackupFile)) {
        Write-Caution "No backup found at $BackupFile. Network settings cannot be restored automatically."
        Remove-Item -LiteralPath $StartupScript -Force -ErrorAction SilentlyContinue
        return
    }

    $backup = Get-Content -LiteralPath $BackupFile -Raw | ConvertFrom-Json

    Write-Step 'Restoring the startup launcher'
    Restore-StartupLauncher

    Write-Step 'Restoring DNS-over-HTTPS'
    Restore-DohSettings -Backup $backup

    Write-Step 'Restoring DNS settings'
    Restore-DnsSettings -Backup $backup

    Write-Step 'Restoring the system proxy'
    Restore-ProxySettings -Proxy $backup.Proxy
}

# -----------------------------------------------------------------------------
# Restore-only mode
# -----------------------------------------------------------------------------
function Invoke-RestoreOnly {
    if (-not (Test-Path -LiteralPath $StateFile) -and -not (Test-Path -LiteralPath $BackupFile)) {
        throw 'Security DNS has no recorded backups to restore. Nothing was changed.'
    }

    Stop-AllRouting
    Restore-AllNetworkSettings

    Set-StateValue 'MODE' 'R'
    Set-StateValue 'DNS_RESTORED' $true

    Write-Host ''
    Write-Good 'Original settings restored. The app, dependencies, and shortcuts are still installed.'
}

# -----------------------------------------------------------------------------
# Full uninstall
# -----------------------------------------------------------------------------
function Remove-MsiProduct([string]$ProductCode, [string]$Label) {
    if (-not $ProductCode) {
        Write-Caution "$Label product code not recorded; remove it from Apps & features if you no longer need it."
        return
    }
    $proc = Start-Process -FilePath 'msiexec.exe' `
        -ArgumentList @('/x', $ProductCode, '/qn', '/norestart') -Wait -PassThru
    if ($proc.ExitCode -in 0, 3010) {
        Write-Good "$Label removed"
    } else {
        Write-Caution "Could not remove $Label (exit code $($proc.ExitCode)). Remove it from Apps & features."
    }
}

function Remove-WarpArtifacts {
    if (Test-Path -LiteralPath $WarpCli) {
        if (Get-StateValue 'WARP_REGISTERED_BY_US') {
            & $WarpCli --accept-tos registration delete *> $null
        }
    }
    if (Get-StateValue 'WARP_MSI_ADDED') {
        Remove-MsiProduct -ProductCode (Get-StateValue 'WARP_PRODUCT_CODE') -Label 'Cloudflare WARP client'
    } else {
        Write-Good 'Cloudflare WARP was not installed by Security DNS; the client was left in place'
    }
}

function Remove-WireGuardArtifacts {
    if (Get-StateValue 'WG_CLIENT_ADDED') {
        Remove-MsiProduct -ProductCode (Get-StateValue 'WG_PRODUCT_CODE') -Label 'WireGuard client'
    }
}

function Remove-Shortcuts {
    $shortcuts = Get-StateValue 'SHORTCUTS'
    foreach ($path in @($shortcuts)) {
        if ($path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    }
    if ($shortcuts) { Write-Good 'Start Menu and Desktop shortcuts removed' }
}

function Invoke-Uninstall {
    Stop-AllRouting

    Write-Step 'Reverting Cloudflare WARP and WireGuard'
    Remove-WarpArtifacts
    Remove-WireGuardArtifacts

    Write-Step 'Removing shortcuts'
    Remove-Shortcuts

    Restore-AllNetworkSettings

    Write-Step 'Cleaning up'
    Clear-DnsClientCache
    ipconfig /flushdns | Out-Null
    Remove-Item -LiteralPath $AppDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Good 'Security DNS files and backups removed'

    Write-Host ''
    Write-Good 'Your system has been returned to its previous state.'
    Write-Host 'Restart your browsers so they stop using the proxy.'
}

# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
if ($RestoreOnly) {
    Invoke-RestoreOnly
} else {
    Invoke-Uninstall
}
