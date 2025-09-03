# Microsoft Defender Exclusions Enumeration

This repository provides several PowerShell techniques for enumerating Microsoft Defender Antivirus exclusions, both with **administrative privileges** and **non-administrative access**.

**Excluded Path for testing**

<img width="1077" height="478" alt="image" src="https://github.com/user-attachments/assets/6537840c-2934-4a9f-8e31-cd6fb9148bee" />

---

## 📌 With Administrative Access

The most direct way to retrieve exclusions is via the built-in `Get-MpPreference` cmdlet.  
Requires **administrative privileges**
```powershell
function Get-DefenderExclusionsAdmin {
    <#
    .SYNOPSIS
    Retrieves the current Microsoft Defender Antivirus exclusions.

    .DESCRIPTION
    This function uses the Get-MpPreference cmdlet to retrieve all configured
    exclusions for Microsoft Defender Antivirus, including file paths,
    extensions, and processes.

    .NOTES
    Requires administrative privileges to run.
    #>
    param()

    Write-Host "Retrieving Microsoft Defender Antivirus Exclusions..."

    try {
        $defenderPreferences = Get-MpPreference

        $exclusions = @{
            "ExclusionPath" = $defenderPreferences.ExclusionPath
            "ExclusionExtension" = $defenderPreferences.ExclusionExtension
            "ExclusionProcess" = $defenderPreferences.ExclusionProcess
        }

        # Display the exclusions
        foreach ($key in $exclusions.Keys) {
            if ($exclusions.$key) {
                # Corrected line: use curly braces around the variable
                Write-Host "`n${key}:"
                $exclusions.$key | ForEach-Object { Write-Host "  - $_" }
            } else {
                # Corrected line: use curly braces around the variable
                Write-Host "`nNo ${key} exclusions found."
            }
        }
    }
    catch {
        Write-Error "An error occurred while retrieving Defender exclusions: $($_.Exception.Message)"
    }
}
```
<img width="930" height="322" alt="image" src="https://github.com/user-attachments/assets/4bc21700-bf89-4346-9e4a-83fe9d55dacd" />

## 📌 Without Administrative Access

Even without admin privileges, exclusions can be identified by parsing the **Windows Defender event logs** (`Microsoft-Windows-Windows Defender/Operational`, Event ID `5007`).

### Example one-liners

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=5007)]]" | 
    Where-Object { $_.Message -like "*exclusions\Path*" } | 
    Select-Object Message | FL
```

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
    Where-Object { $_.Id -eq 5007 -and $_.Message -match "Exclusions" } |
    ForEach-Object {
        if ($_.Message -match "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([^\s]+)") {
            $matches[1]
        }
    }
```
<img width="1817" height="698" alt="image" src="https://github.com/user-attachments/assets/b4f3274b-840a-4ebc-b75d-7503e2eec4e1" />

---

### Full Event Log Parsing Function

```powershell
function Get-DefenderExclusions {
    param (
        [string]$LogName = "Microsoft-Windows-Windows Defender/Operational",
        [int]$EventID = 5007
    )

    # Get all event logs with the specified Event ID
    $events = Get-WinEvent -LogName $LogName | Where-Object { $_.Id -eq $EventID }

    # Filter events that contain the word "Exclusions"
    $exclusionEvents = $events | Where-Object { $_.Message -match "Exclusions" }

    # Define the regex pattern to match exclusion paths, extensions, and processes
    $patternPaths      = "Exclusions\\Paths\\[^\s]+"
    $patternExtensions = "Exclusions\\Extensions\\[^\s]+"
    $patternProcesses  = "Exclusions\\Processes\\[^\s]+"

    # Extract and print all types of exclusions from the message
    $exclusionEvents | ForEach-Object {
        $message = $_.Message

        # Check and extract Path exclusions
        if ($message -match $patternPaths) {
            [PSCustomObject]@{
                TimeCreated    = $_.TimeCreated
                ExclusionType  = 'Path'
                ExclusionDetail = $matches[0]
            }
        }

        # Check and extract Extension exclusions
        if ($message -match $patternExtensions) {
            [PSCustomObject]@{
                TimeCreated    = $_.TimeCreated
                ExclusionType  = 'Extension'
                ExclusionDetail = $matches[0]
            }
        }

        # Check and extract Process exclusions
        if ($message -match $patternProcesses) {
            [PSCustomObject]@{
                TimeCreated    = $_.TimeCreated
                ExclusionType  = 'Process'
                ExclusionDetail = $matches[0]
            }
        }
    }
}

```
<img width="1142" height="244" alt="image" src="https://github.com/user-attachments/assets/d827188a-6306-4be4-aba1-bc91d52f6280" />

### Alternative Version with Filtering

```powershell
function Get-DefenderExclusions {
    param (
        [string]$logName = "Microsoft-Windows-Windows Defender/Operational",
        [int]$eventID = 5007,
        [switch]$Path,
        [switch]$Process,
        [switch]$Extension
    )

    if (-not ($Path -or $Process -or $Extension)) {
        Write-Host "Please specify at least one type of exclusion to filter: -Path, -Process, -Extension."
        return
    }

    # Get all event logs with the specified Event ID
    $events = Get-WinEvent -LogName $logName -FilterXPath "*[System[(EventID=$eventID)]]" -ErrorAction SilentlyContinue

    if (-not $events) {
        Write-Host "No events found with Event ID $eventID in the $logName log."
        return
    }

    # Define the regex patterns for exclusion paths, extensions, and processes
    $patterns = @{
        Path = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([^`"]+)"
        Extension = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions\\([^`"]+)"
        Process = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\([^`"]+)"
    }

    # Function to parse and return unique exclusions
    function Get-UniqueExclusions {
        param (
            [string]$pattern,
            [string]$exclusionType
        )

        $uniqueExclusions = @{}
        foreach ($event in $events) {
            $message = $event.Message
            if ($message -match $pattern) {
                $exclusionDetail = $matches[1] -replace ' = 0x0.*$', '' -replace 'New value:', '' -replace '^\s+|\s+$', ''
                if (-not $uniqueExclusions.ContainsKey($exclusionDetail) -or $event.TimeCreated -gt $uniqueExclusions[$exclusionDetail]) {
                    $uniqueExclusions[$exclusionDetail] = $event.TimeCreated
                }
            }
        }
        return $uniqueExclusions.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            [PSCustomObject]@{
                ExclusionDetail = $_.Key
                TimeCreated = $_.Value
            }
        }
    }

    # Extract and display exclusions based on the provided arguments
    if ($Path) {
        Write-Host "Path Exclusions:"
        Get-UniqueExclusions -pattern $patterns.Path -exclusionType 'Path' | Format-Table -Property ExclusionDetail, TimeCreated -AutoSize -Wrap
    }
    if ($Process) {
        Write-Host "Process Exclusions:"
        Get-UniqueExclusions -pattern $patterns.Process -exclusionType 'Process' | Format-Table -Property ExclusionDetail, TimeCreated -AutoSize -Wrap
    }
    if ($Extension) {
        Write-Host "Extension Exclusions:"
        Get-UniqueExclusions -pattern $patterns.Extension -exclusionType 'Extension' | Format-Table -Property ExclusionDetail, TimeCreated -AutoSize -Wrap
    }
}
```
---

## 📌 Alternative Technique (MpCmdRun.exe)

Another trick is to abuse Defender’s `MpCmdRun.exe` with an **invalid path (`|*`)**.
This allows detecting exclusions by checking the response.

```powershell
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
```


* If the folder is **excluded**, you’ll see:
  `Scanning C:\Share\|* was skipped.`
* If not excluded → Error `0x80508023`
* If invalid target → Error `0x80004005`
  
<img width="1151" height="142" alt="image" src="https://github.com/user-attachments/assets/36b7d769-913a-400a-948f-503cd48eba32" />

---

## ⚠️ Notes

* Administrative access gives the most reliable results.
* Non-admin techniques rely on event logs, which may not always contain the full exclusion list.
* The `MpCmdRun.exe` trick is useful for **runtime testing** but may return access errors on root drives.

---

## ✅ Summary

| Technique            | Admin Required | Method                                 |                                 |
| -------------------- | -------------- | -------------------------------------- | ------------------------------- |
| `Get-MpPreference`   | ✅ Yes          | Directly queries Defender preferences  |                                 |
| Event Logs (ID 5007) | ❌ No           | Parses Defender registry change events |                                 |
| `MpCmdRun.exe` \`    | \*\` trick     | ❌ No                                   | Tests runtime scanning behavior |

---

