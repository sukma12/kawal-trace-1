# Kawal-Trace Windows Event Log agent launcher.
# Run only from a signed/ACL-protected installation folder with a SYSTEM/Admin-only env file.
$ErrorActionPreference = 'Stop'
$programData = [Environment]::GetFolderPath('CommonApplicationData')
$envFile = Join-Path $programData 'Kawal-Trace\agent.env'
if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw "Missing protected configuration: $envFile"
}
# Parse simple KEY=value lines; first '=' separates key from value so base64 padding is preserved.
Get-Content -LiteralPath $envFile | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#') -or -not $line.Contains('=')) { return }
    $pair = $line.Split(@('='), 2, [System.StringSplitOptions]::None)
    $name = $pair[0].Trim()
    $value = $pair[1].Trim()
    if ($name -match '^KAWAL_[A-Z0-9_]+$') { [Environment]::SetEnvironmentVariable($name, $value, 'Process') }
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = [Environment]::GetEnvironmentVariable('KAWAL_WIN_PYTHON', 'Process')
if (-not $python) { $python = Join-Path $projectRoot '.venv\Scripts\python.exe' }
$agentScript = Join-Path $PSScriptRoot 'eventlog_agent.py'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "Python interpreter not found: $python" }
if (-not (Test-Path -LiteralPath $agentScript -PathType Leaf)) { throw "Agent script not found: $agentScript" }
$env:PYTHONPATH = $projectRoot
Set-Location -LiteralPath $projectRoot
& $python $agentScript
exit $LASTEXITCODE
