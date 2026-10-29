param(
    [string]$Version = 'latest',
    [string]$Binary = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = 'KilluaAoki/XNode'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Please run from an elevated PowerShell (Run as Administrator)' -ForegroundColor Red
    exit 1
}

$ProgramDir = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$Installed = Join-Path $ProgramDir 'xnode\xnode.exe'
if ($args.Count -eq 0 -and -not $Binary -and $Version -eq 'latest' -and (Test-Path $Installed)) {
    & $Installed menu
    exit $LASTEXITCODE
}

$cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($cpu) {
    'AMD64' { $Arch = '64' }
    'ARM64' { $Arch = 'arm64-v8a' }
    default {
        Write-Host "Unsupported architecture: $cpu" -ForegroundColor Red
        exit 1
    }
}

$TmpDir = Join-Path ([IO.Path]::GetTempPath()) ('xnode-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TmpDir | Out-Null
try {
    if ($Binary) {
        $Staged = (Resolve-Path $Binary).Path
    } else {
        $Asset = "xnode-windows-$Arch.zip"
        if ($Version -eq 'latest') {
            $Url = "https://github.com/$Repo/releases/latest/download/$Asset"
        } else {
            $Url = "https://github.com/$Repo/releases/download/$Version/$Asset"
        }
        Write-Host "Downloading $Url"
        $Archive = Join-Path $TmpDir $Asset
        Invoke-WebRequest -Uri $Url -OutFile $Archive -UseBasicParsing
        Expand-Archive -Path $Archive -DestinationPath $TmpDir -Force
        $Staged = Join-Path $TmpDir 'xnode.exe'
    }
    & $Staged install @args
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    Write-Host 'XNode installed; open a new terminal to use xnode from PATH' -ForegroundColor Green
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
