$ErrorActionPreference = "Stop"
$env:LOG_LEVEL = "debug"

Write-Host "Running program with debug logs..."
.\chatlog.exe > debug.log 2>&1

Write-Host "Program stopped. Debug log saved to debug.log"
Write-Host "Last 200 lines of log:"
Get-Content -Path debug.log -Tail 200