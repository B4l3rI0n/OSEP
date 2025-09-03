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
