#Requires -Version 5.1
<#
.SYNOPSIS
    Security DNS - Windows installer.

.DESCRIPTION
    Installs SpoofDPI as a hidden local proxy, enables system-wide DNS-over-HTTPS
    through Cloudflare (1.1.1.1), points the system proxy at the local SpoofDPI
    instance, and backs up every setting it changes. Use -Uninstall to restore
    the exact previous state.

.PARAMETER Uninstall
    Reverts all changes made by this installer. Alias: -Revert.

.EXAMPLE
    irm https://raw.githubusercontent.com/arcalc/setup_privacy/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [Alias('Revert')]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
$RepoRaw        = 'https://raw.githubusercontent.com/arcalc/setup_privacy/main'
$SpoofDpiRepo   = 'xvzc/SpoofDPI'
$SpoofDpiFlags  = if ($env:SPOOFDPI_EXTRA_FLAGS) { $env:SPOOFDPI_EXTRA_FLAGS } else { '' }
$DataRoot       = Join-Path $env:ProgramData 'SecurityDNS'
$BinDir         = Join-Path $DataRoot 'bin'
$BackupDir      = Join-Path $DataRoot 'backup'
$BackupFile     = Join-Path $BackupDir 'pre-install.json'
$StartupDir     = [Environment]::GetFolderPath('Startup')
$StartupScript  = Join-Path $StartupDir 'security-dns.vbs'
$ProxyKey       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$PortCandidates = @(8080, 8081)
$MinDohBuild    = 19041
$CloudflareDoh  = [ordered]@{
    '1.1.1.1'              = 'https://cloudflare-dns.com/dns-query'
    '1.0.0.1'              = 'https://cloudflare-dns.com/dns-query'
    '2606:4700:4700::1111' = 'https://cloudflare-dns.com/dns-query'
    '2606:4700:4700::1001' = 'https://cloudflare-dns.com/dns-query'
}

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
    throw 'Security DNS must run from an elevated PowerShell session. Right-click PowerShell and choose "Run as administrator".'
}

# -----------------------------------------------------------------------------
# Shared helpers
# -----------------------------------------------------------------------------
function Get-RegistryValue([string]$Path, [string]$Name) {
    $item   = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $exists = ($null -ne $item) -and ($item.PSObject.Properties.Name -contains $Name)
    $value  = $null
    if ($exists) { $value = $item.$Name }
    return [pscustomobject]@{ Exists = $exists; Value = $value }
}

function Update-WinInet {
    if (-not ('SecurityDns.WinInet' -as [type])) {
        Add-Type -Namespace SecurityDns -Name WinInet -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
    }
    # 39 = INTERNET_OPTION_SETTINGS_CHANGED, 37 = INTERNET_OPTION_REFRESH
    [void][SecurityDns.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][SecurityDns.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
}

function Test-DohSupported {
    $build  = [int](Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
    $hasCmd = [bool](Get-Command -Name Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
    return [pscustomobject]@{ Build = $build; Supported = (($build -ge $MinDohBuild) -and $hasCmd) }
}

function Test-PortInUse([int]$Port) {
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

function Select-LocalPort {
    foreach ($port in $PortCandidates) {
        if (-not (Test-PortInUse $port)) { return $port }
        Write-Caution "Port $port is already in use."
    }
    throw 'Neither port 8080 nor 8081 is free. Free one of them and run the installer again.'
}

function Get-SpoofDpiArguments([int]$Port) {
    return "--listen-addr 127.0.0.1:$Port $SpoofDpiFlags".Trim()
}

function Stop-SpoofDpi {
    Get-Process -Name 'spoofdpi' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
# Download and verification
# -----------------------------------------------------------------------------
function Get-SpoofDpiRelease {
    $headers = @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'security-dns-installer' }
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$SpoofDpiRepo/releases/latest" -Headers $headers
    $assets  = @($release.assets)

    $bin = $assets |
        Where-Object { $_.name -match 'windows' -and $_.name -match 'amd64' -and $_.name -match '\.(zip|exe)$' } |
        Sort-Object { $_.name -notmatch '\.zip$' } |
        Select-Object -First 1
    if (-not $bin) { throw "No windows-amd64 asset found in SpoofDPI release $($release.tag_name)." }

    $sums = $assets |
        Where-Object { $_.name -match 'sha256|checksum' -and $_.name -notmatch 'linux|darwin|macos|arm' } |
        Select-Object -First 1

    $sumsUrl = $null
    if ($sums) { $sumsUrl = $sums.browser_download_url }

    return [pscustomobject]@{
        Tag     = $release.tag_name
        Name    = $bin.name
        Url     = $bin.browser_download_url
        SumsUrl = $sumsUrl
    }
}

function Test-FileSha256([string]$File, [string]$SumsFile, [string]$Name) {
    $lines = @(Get-Content -LiteralPath $SumsFile | Where-Object { $_.Trim() })
    $line  = $lines | Where-Object { $_ -match [regex]::Escape($Name) } | Select-Object -First 1
    if (-not $line -and $lines.Count -gt 0) { $line = $lines[0] }

    $expected = ([string]$line -split '\s+')[0]
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') {
        Write-Caution 'Checksum file could not be parsed; skipping verification.'
        return
    }

    $actual = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash
    if ($actual -ne $expected.ToUpperInvariant()) { throw "SHA-256 mismatch for $Name. Refusing to install." }
    Write-Good 'SHA-256 checksum verified.'
}

function Install-SpoofDpiBinary {
    $release = Get-SpoofDpiRelease
    Write-Good "Latest SpoofDPI release: $($release.Tag)"

    $tmp = Join-Path $env:TEMP ('sdns-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $file = Join-Path $tmp $release.Name
        Invoke-WebRequest -Uri $release.Url -OutFile $file -UseBasicParsing

        if ($release.SumsUrl) {
            $sumsFile = Join-Path $tmp 'checksums.txt'
            Invoke-WebRequest -Uri $release.SumsUrl -OutFile $sumsFile -UseBasicParsing
            Test-FileSha256 -File $file -SumsFile $sumsFile -Name $release.Name
        } else {
            Write-Caution 'No checksum published for this release; integrity was not verified.'
        }

        if ($file -like '*.zip') {
            $extract = Join-Path $tmp 'extract'
            Expand-Archive -LiteralPath $file -DestinationPath $extract -Force
            $exe = Get-ChildItem -LiteralPath $extract -Recurse -Filter 'spoofdpi*.exe' | Select-Object -First 1
            if (-not $exe) { throw 'spoofdpi.exe was not found inside the downloaded archive.' }
            $source = $exe.FullName
        } else {
            $source = $file
        }

        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination (Join-Path $BinDir 'spoofdpi.exe') -Force
        Write-Good "Installed SpoofDPI $($release.Tag) to $BinDir"
    }
    finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -----------------------------------------------------------------------------
# Backup
# -----------------------------------------------------------------------------
function Save-PreInstallState {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    if (Test-Path -LiteralPath $BackupFile) {
        Write-Good 'Original backup already exists; keeping it.'
        return
    }

    $proxy = [ordered]@{
        ProxyEnable   = Get-RegistryValue $ProxyKey 'ProxyEnable'
        ProxyServer   = Get-RegistryValue $ProxyKey 'ProxyServer'
        ProxyOverride = Get-RegistryValue $ProxyKey 'ProxyOverride'
        AutoConfigURL = Get-RegistryValue $ProxyKey 'AutoConfigURL'
    }

    $dns = foreach ($adapter in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        $cfg = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
            -Filter "InterfaceIndex = $($adapter.ifIndex)" -ErrorAction SilentlyContinue
        if ($cfg) {
            [pscustomobject]@{
                InterfaceIndex = [int]$adapter.ifIndex
                Alias          = $adapter.Name
                Dhcp           = [bool]$cfg.DHCPEnabled
                Servers        = @($cfg.DNSServerSearchOrder | Where-Object { $_ })
            }
        }
    }

    $doh = @()
    if (Get-Command -Name Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
        $doh = @(Get-DnsClientDohServerAddress | ForEach-Object {
            [pscustomobject]@{
                ServerAddress      = $_.ServerAddress
                DohTemplate        = $_.DohTemplate
                AllowFallbackToUdp = [bool]$_.AllowFallbackToUdp
                AutoUpgrade        = [bool]$_.AutoUpgrade
            }
        })
    }

    $startupExisted = Test-Path -LiteralPath $StartupScript
    if ($startupExisted) {
        Copy-Item -LiteralPath $StartupScript -Destination (Join-Path $BackupDir 'security-dns.vbs.orig') -Force
    }

    $state = [ordered]@{
        Version = 1
        Created = (Get-Date).ToString('o')
        Proxy   = $proxy
        Dns     = @($dns | Where-Object { $_ })
        Doh     = $doh
        Startup = [pscustomobject]@{ Existed = $startupExisted }
    }
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $BackupFile -Encoding UTF8
    Write-Good "Backed up network, DNS and proxy settings to $BackupFile"
}

# -----------------------------------------------------------------------------
# Configuration changes
# -----------------------------------------------------------------------------
function Set-SecureDns {
    $info = Test-DohSupported
    if (-not $info.Supported) {
        Write-Caution "This Windows build ($($info.Build)) does not support system-wide DNS-over-HTTPS."
        Write-Caution "It requires build $MinDohBuild (Windows 10 version 2004) or newer."
        Write-Caution 'System DNS was NOT changed, so no plaintext queries are sent to 1.1.1.1.'
        Write-Caution 'Enable Secure DNS in your browser instead (see the README troubleshooting section).'
        return $false
    }

    foreach ($address in $CloudflareDoh.Keys) {
        Remove-DnsClientDohServerAddress -ServerAddress $address -ErrorAction SilentlyContinue
        Add-DnsClientDohServerAddress -ServerAddress $address `
            -DohTemplate $CloudflareDoh[$address] `
            -AllowFallbackToUdp $false `
            -AutoUpgrade $true
    }
    Write-Good 'Cloudflare DNS-over-HTTPS templates registered.'

    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) {
        Write-Caution 'No active physical network adapters found; DNS was not changed.'
        return $true
    }

    $servers = @($CloudflareDoh.Keys)
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $servers
        Write-Good "DNS-over-HTTPS enabled on '$($adapter.Name)'"
    }

    Clear-DnsClientCache
    return $true
}

function Set-SystemProxy([int]$Port) {
    $server = "127.0.0.1:$Port"

    if ((Get-RegistryValue $ProxyKey 'AutoConfigURL').Exists) {
        Write-Caution 'An automatic configuration (PAC) URL was set. It is disabled so the proxy takes effect; the original value is backed up.'
    }
    Remove-ItemProperty -Path $ProxyKey -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $ProxyKey -Name 'ProxyServer'   -Value $server -Type String
    Set-ItemProperty -Path $ProxyKey -Name 'ProxyOverride' -Value 'localhost;127.*;10.*;192.168.*;<local>' -Type String
    Set-ItemProperty -Path $ProxyKey -Name 'ProxyEnable'   -Value 1 -Type DWord

    Update-WinInet
    Write-Good "System proxy set to $server"
}

function Install-StartupLauncher([int]$Port) {
    $exe         = Join-Path $BinDir 'spoofdpi.exe'
    $spoofArgs   = Get-SpoofDpiArguments -Port $Port
    $launcherVbs = @"
' Security DNS - hidden launcher for SpoofDPI. Managed by setup_privacy; removed on uninstall.
Set shell = CreateObject("WScript.Shell")
shell.Run """$exe"" $spoofArgs", 0, False
"@

    New-Item -ItemType Directory -Path $StartupDir -Force | Out-Null
    Set-Content -LiteralPath $StartupScript -Value $launcherVbs -Encoding ASCII
    Write-Good "Hidden startup launcher created: $StartupScript"
}

function Start-Proxy([int]$Port) {
    $exe       = Join-Path $BinDir 'spoofdpi.exe'
    $spoofArgs = Get-SpoofDpiArguments -Port $Port
    Start-Process -FilePath $exe -ArgumentList $spoofArgs -WindowStyle Hidden

    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-PortInUse $Port) {
            Write-Good "SpoofDPI is listening on 127.0.0.1:$Port"
            return
        }
    }
    throw "SpoofDPI did not start on 127.0.0.1:$Port. Run $exe $spoofArgs manually to see the error."
}

# -----------------------------------------------------------------------------
# Uninstall dispatch
# -----------------------------------------------------------------------------
function Invoke-Uninstaller {
    $localUninstall = $null
    if ($PSScriptRoot) { $localUninstall = Join-Path $PSScriptRoot 'uninstall.ps1' }

    if ($localUninstall -and (Test-Path -LiteralPath $localUninstall)) {
        & $localUninstall
    } else {
        $remote = Join-Path $env:TEMP 'security-dns-uninstall.ps1'
        Invoke-WebRequest -Uri "$RepoRaw/uninstall.ps1" -OutFile $remote -UseBasicParsing
        & $remote
    }
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
function Invoke-Install {
    Write-Step 'Preparing'
    New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null
    Save-PreInstallState

    Write-Step 'Stopping any previous SpoofDPI instance'
    Stop-SpoofDpi

    Write-Step 'Selecting a local port'
    $port = Select-LocalPort
    Write-Good "Using 127.0.0.1:$port"

    Write-Step 'Installing SpoofDPI'
    Install-SpoofDpiBinary

    Write-Step 'Creating startup launcher and starting the proxy'
    Install-StartupLauncher -Port $port
    Start-Proxy -Port $port

    Write-Step 'Configuring secure DNS'
    $dnsChanged = Set-SecureDns

    Write-Step 'Configuring the system proxy'
    Set-SystemProxy -Port $port

    Set-Content -LiteralPath (Join-Path $DataRoot 'port.txt') -Value $port -Encoding ASCII

    Write-Host ''
    Write-Good 'Security DNS installation complete.'
    Write-Host "  Local proxy : 127.0.0.1:$port (hidden, starts when you sign in)"
    if ($dnsChanged) {
        Write-Host '  DNS         : DNS-over-HTTPS via 1.1.1.1 / 1.0.0.1, no plaintext fallback'
    } else {
        Write-Host '  DNS         : unchanged (enable Secure DNS in your browser)'
    }
    Write-Host '  Proxy       : system proxy enabled'
    Write-Host ''
    Write-Host 'Next steps:' -ForegroundColor White
    Write-Host '  1. Restart your browsers completely.'
    Write-Host '  2. Enable ECH and disable QUIC/HTTP3 in your browser (see README.md).'
    Write-Host '  3. Apps that ignore the system proxy will connect directly.'
    Write-Host ''
    Write-Caution 'Your ISP can still see destination IP addresses and traffic volume.'
    Write-Host ''
    Write-Host 'Revert everything with: .\install.ps1 -Uninstall'
}

if ($Uninstall) {
    Invoke-Uninstaller
    return
}

Invoke-Install
