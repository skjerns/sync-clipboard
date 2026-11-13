# ClipSend installer for Windows (current user only, no administrator rights needed).
#
# Uses an existing Python 3 installation. Without Python, use ClipSend.exe instead:
# double-click it and choose "Install".
#
#   install-windows.bat              install (or upgrade) and start ClipSend
#   install-windows.bat -Uninstall   remove it again (settings are kept)

param([switch]$Uninstall)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Find-Python {
    # 'py' launcher first; skip the Microsoft Store 'python' alias stub (it has no real sys.executable)
    foreach ($cmd in @(@('py', '-3'), @('python'))) {
        try {
            $exe = & $cmd[0] @($cmd | Select-Object -Skip 1) -c 'import sys; print(sys.executable)' 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe -and (Test-Path -LiteralPath $exe.Trim())) { return $exe.Trim() }
        } catch { }
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Write-Host 'Python 3 was not found.' -ForegroundColor Red
    Write-Host 'Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH"),'
    Write-Host 'or use ClipSend.exe, which needs no Python.'
    exit 1
}
Write-Host "Using Python: $py"

if ($Uninstall) {
    $installed = Join-Path $env:LOCALAPPDATA 'Programs\ClipSend\clipsendx.py'
    $script = if (Test-Path -LiteralPath $installed) { $installed } else { Join-Path $PSScriptRoot 'clipsendx.py' }
    & $py $script --uninstall
    exit $LASTEXITCODE
}

Write-Host 'Installing Python packages (PySide6, requests, cryptography, websocket-client) ...'
& $py -m pip install --user --upgrade --disable-pip-version-check --quiet `
    PySide6 requests cryptography websocket-client
if ($LASTEXITCODE -ne 0) { Write-Host 'pip install failed.' -ForegroundColor Red; exit 1 }

if (Test-Path -LiteralPath 'credentials.json') {
    & $py clipsendx.py --import-legacy credentials.json
}

& $py clipsendx.py --install
if ($LASTEXITCODE -ne 0) { Write-Host 'Installation failed.' -ForegroundColor Red; exit 1 }

Write-Host ''
Write-Host 'Done. ClipSend is running (look for the tray icon, it may be in the ^ overflow area),' -ForegroundColor Green
Write-Host 'starts automatically when you log in and is in the Start Menu.'
Write-Host 'Uninstall via Settings > Apps > Installed apps, or: install-windows.bat -Uninstall'
