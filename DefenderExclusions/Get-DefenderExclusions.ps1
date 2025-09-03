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
