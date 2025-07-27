param(
    [string]$ip,
    [int]$port,
    [string]$app
)

New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null

$keys = Get-ChildItem 'HKU:\'
foreach ($key in $keys) {
    if ($key.Name -like "*S-1-5-21-*") {
        $start = $key.Name.Substring(10)
        break
    }
}

$proxyAddr = (Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
if (![string]::IsNullOrWhiteSpace($proxyAddr)) {
    # If multiple proxies are set (separated by semicolons), use the first one
    $firstProxy = $proxyAddr.Split(';')[0]
    
    try {
        [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy("http://$firstProxy")
    } catch {
        Write-Error "Proxy string '$firstProxy' is not a valid URI."
        exit
    }
} else {
    Write-Host "No proxy address found in registry. Continuing without proxy."
}

$url = "http://$ip`:$port/$app"
$dest = Join-Path -Path (Get-Location) -ChildPath (Split-Path $app -Leaf)

$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $dest)
