param(
    [Parameter(Mandatory=$true)]
    [string]$Folder
)

$DefenderPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"

# Build command
$ScanCommand = "& `"$DefenderPath`" -Scan -ScanType 3 -File `"$Folder\|*`""

# Capture output
$Output = Invoke-Expression $ScanCommand 2>&1

# Detection logic
if ($Output -match "was skipped") {
    Write-Host "[+] Excluded: $Folder" -ForegroundColor Green
}
elseif ($Output -match "0x80508023") {
    Write-Host "[-] Not Excluded: $Folder" -ForegroundColor Red
}
elseif ($Output -match "0x80004005") {
    Write-Host "[!] Error: Access denied or invalid scan target ($Folder)" -ForegroundColor Yellow
}
else {
    Write-Host "[?] Unknown result while checking $Folder" -ForegroundColor Yellow
    Write-Output $Output
}
