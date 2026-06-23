import re
from .filesystem import MockFilesystem
from .scenarios import SCENARIOS

class TerminalSession:
    def __init__(self, scenario_id):
        self.scenario_id = scenario_id
        self.fs = MockFilesystem()
        self.registry = {}
        self.escalated = False
        
        # Load scenario settings
        scenario = SCENARIOS.get(scenario_id)
        if not scenario:
            raise ValueError(f"Unknown scenario ID {scenario_id}")
            
        self.os = scenario.category # "Windows" or "Linux"
        scenario.setup(self.fs, self.registry)
        
        self.current_user = scenario.initial_user
        
        # Map initial directories properly
        if self.os == "Linux":
            self.current_dir = "/home/student"
            self.uid = 1000
            self.gid = 1000
            self.groups = ["student", "users"]
            # Add docker group for Lab 23
            if scenario_id == 23:
                self.groups.append("docker")
        else:
            # Windows
            self.current_dir = scenario.initial_dir
            self.groups = ["Users"]
            self.privileges = [
                {"name": "SeChangeNotifyPrivilege", "desc": "Bypass traverse checking", "status": "Enabled"},
                {"name": "SeShutdownPrivilege", "desc": "Shut down the system", "status": "Disabled"}
            ]
            
            if self.current_user == "local service":
                self.groups = ["SERVICE", "Authenticated Users"]
                self.privileges = [
                    {"name": "SeAssignPrimaryTokenPrivilege", "desc": "Replace a process level token", "status": "Disabled"},
                    {"name": "SeIncreaseQuotaPrivilege", "desc": "Adjust memory quotas for a process", "status": "Disabled"},
                    {"name": "SeChangeNotifyPrivilege", "desc": "Bypass traverse checking", "status": "Enabled"},
                    {"name": "SeImpersonatePrivilege", "desc": "Impersonate a client after authentication", "status": "Enabled"},
                    {"name": "SeCreateGlobalPrivilege", "desc": "Create global objects", "status": "Enabled"}
                ]

        # Windows Services setup
        self.services = {
            "VulnService": {
                "name": "VulnService", "display_name": "Vulnerable Application Service",
                "type": "10  WIN32_OWN_PROCESS", "start_type": "2   AUTO_START", "status": "STOPPED",
                "path": "C:\\Program Files\\Vulnerable Software\\Vulnerable Service.exe", "user": "LocalSystem"
            },
            "WeakService": {
                "name": "WeakService", "display_name": "Configurable Service",
                "type": "10  WIN32_OWN_PROCESS", "start_type": "3   DEMAND_START", "status": "STOPPED",
                "path": "C:\\Windows\\System32\\svchost.exe", "user": "LocalSystem"
            },
            "WeakACLService": {
                "name": "WeakACLService", "display_name": "Insecure Executable Service",
                "type": "10  WIN32_OWN_PROCESS", "start_type": "3   DEMAND_START", "status": "STOPPED",
                "path": "C:\\Program Files\\WeakACL\\service.exe", "user": "LocalSystem"
            },
            "RegService": {
                "name": "RegService", "display_name": "Registry Service Helper",
                "type": "10  WIN32_OWN_PROCESS", "start_type": "3   DEMAND_START", "status": "STOPPED",
                "path": "C:\\Program Files\\RegService\\service.exe", "user": "LocalSystem"
            }
        }
        
        # Linux PATH variable helper
        self.linux_path = "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"

    # Map UNIX paths to inner Windows NTFS mock nodes
    def to_win_path(self, unix_path):
        if not unix_path:
            return ""
        
        # Absolute or relative
        path = unix_path.strip()
        if not path.startswith("/"):
            # Relative to current UNIX directory
            path = self.current_dir + "/" + path
            
        # Clean double slashes
        path = re.sub(r'/+', '/', path)
        
        # Handle parent directories (..)
        parts = path.split('/')
        resolved_parts = []
        for p in parts:
            if p == "..":
                if resolved_parts:
                    resolved_parts.pop()
            elif p != "." and p != "":
                resolved_parts.append(p)
                
        # Remap to NTFS format
        win_path = "C:\\" + "\\".join(resolved_parts)
        return win_path

    def to_unix_path(self, win_path):
        if not win_path:
            return "/"
        path = win_path.replace("C:\\", "").replace("\\", "/")
        if not path.startswith("/"):
            path = "/" + path
        return path

    def execute_command(self, cmd_line):
        cmd_line = cmd_line.strip()
        if not cmd_line:
            return "", "", self.current_dir

        if self.os == "Windows":
            return self._execute_windows(cmd_line)
        else:
            return self._execute_linux(cmd_line)

    # ==========================================
    # WINDOWS COMMAND ROUTER
    # ==========================================
    def _execute_windows(self, cmd_line):
        tokens = re.findall(r'(?:[^\s"]+|"[^"]*")+', cmd_line)
        if not tokens:
            return "", "", self.current_dir
            
        args = [t.strip('"') for t in tokens]
        cmd = args[0].lower()
        
        # PowerShell checks
        if cmd in ["powershell", "powershell.exe"]:
            if len(args) > 1:
                cmd_idx = -1
                for idx, arg in enumerate(args):
                    if arg.lower() in ["-c", "-command"]:
                        cmd_idx = idx + 1
                        break
                if cmd_idx != -1 and cmd_idx < len(args):
                    return self._execute_windows(args[cmd_idx])
            return "Windows PowerShell\nCopyright (C) Microsoft Corporation.\n\nPS " + self.current_dir + "> ", "", self.current_dir

        if cmd == "whoami":
            return self._win_whoami(args[1:])
        elif cmd == "cd":
            return self._win_cd(args[1:])
        elif cmd in ["dir", "ls"]:
            return self._win_dir(args[1:])
        elif cmd in ["type", "cat"]:
            return self._win_type(args[1:])
        elif cmd == "echo":
            return self._win_echo(cmd_line)
        elif cmd == "mkdir":
            return self._win_mkdir(args[1:])
        elif cmd in ["del", "rm"]:
            return self._win_del(args[1:])
        elif cmd == "icacls":
            return self._win_icacls(args[1:])
        elif cmd == "sc":
            return self._win_sc(args[1:], cmd_line)
        elif cmd == "reg":
            return self._win_reg(args[1:])
        elif cmd == "net":
            return self._win_net(args[1:])
        elif cmd in ["msiexec", "msiexec.exe"]:
            return self._win_msiexec(args[1:])
        elif cmd in ["printspoofer", "printspoofer.exe"]:
            return self._win_printspoofer(args[1:])
        elif cmd in ["juicypotato", "juicypotato.exe"]:
            return self._win_juicypotato(args[1:])
        elif cmd == "cmdkey":
            return self._win_cmdkey(args[1:])
        elif cmd == "runas":
            return self._win_runas(args[1:])
        elif cmd == "fodhelper" or cmd == "fodhelper.exe":
            return self._win_fodhelper()
        elif cmd in ["app.exe", "C:\\Program Files\\App\\app.exe"]:
            return self._win_run_app()
        elif cmd in ["agent.exe", "agent", "C:\\Program Files\\Security Agent\\agent.exe"]:
            return self._trigger_lab_5_exploit()
        elif cmd == "run_script.bat":
            return self._win_run_script()
        elif cmd == "help":
            return self._win_help()
        else:
            # Check executable running
            exe_path = args[0]
            if not exe_path.upper().startswith("C:"):
                exe_path = self.current_dir + "\\" + exe_path
            exe_path = self.fs._normalize_path(exe_path)
            if not exe_path.lower().endswith(".exe") and not exe_path.lower().endswith(".bat"):
                exe_path += ".exe"
                
            if self.fs.exists(exe_path) and not self.fs.is_dir(exe_path):
                # Trigger custom executable check (e.g. Lab 5)
                if self.scenario_id == 5 and "agent.exe" in exe_path.lower():
                    return self._trigger_lab_5_exploit()
                return f"Running: {exe_path}\n[Execution complete]", "", self.current_dir
                
            return "", f"'{args[0]}' is not recognized as an internal or external command.", self.current_dir

    # Windows sub-command handlers
    def _win_whoami(self, args):
        if not args:
            return f"desktop-lab\\{self.current_user}", "", self.current_dir
        arg = args[0].lower()
        if arg == "/priv":
            out = "\nPRIVILEGES INFORMATION\n----------------------\n\n"
            out += f"{'Privilege Name':<35} {'Description':<50} {'State':<10}\n"
            out += f"{'='*35} {'='*50} {'='*10}\n"
            for p in self.privileges:
                out += f"{p['name']:<35} {p['desc']:<50} {p['status']:<10}\n"
            return out, "", self.current_dir
        elif arg == "/groups":
            out = "\nGROUP INFORMATION\n-----------------\n\n"
            out += f"{'Group Name':<35} {'Type':<20} {'SID':<30}\n"
            out += f"{'='*35} {'='*20} {'='*30}\n"
            for g in self.groups:
                out += f"{g:<35} {'Well-known group':<20} {'S-1-5-32-' + str(len(g)):<30}\n"
            return out, "", self.current_dir
        return "", f"Invalid argument: '{args[0]}'", self.current_dir

    def _win_cd(self, args):
        if not args:
            return self.current_dir, "", self.current_dir
        target = args[0]
        new_path = target
        if not target.upper().startswith("C:"):
            if target == "..":
                parts = self.current_dir.split('\\')
                new_path = "\\".join(parts[:-1]) if len(parts) > 1 else "C:\\"
            elif target == ".":
                new_path = self.current_dir
            else:
                new_path = self.current_dir + "\\" + target
                
        new_path = self.fs._normalize_path(new_path)
        if not self.fs.exists(new_path):
            return "", f"The system cannot find the path specified: {target}", self.current_dir
        if not self.fs.is_dir(new_path):
            return "", f"Directory name is invalid.", self.current_dir
            
        node = self.fs._get_node(new_path)
        if not self.fs.has_read_permission(node, self.current_user):
            return "", "Access is denied.", self.current_dir
            
        self.current_dir = new_path
        return "", "", self.current_dir

    def _win_dir(self, args):
        target = self.current_dir
        if args:
            target_arg = args[0]
            target = target_arg if target_arg.upper().startswith("C:") else self.current_dir + "\\" + target_arg
            
        target = self.fs._normalize_path(target)
        if not self.fs.exists(target):
            return "", "File Not Found", self.current_dir
        if not self.fs.is_dir(target):
            node = self.fs._get_node(target)
            return f"Directory of {target}\n\n12/22/2026  07:00 PM    {len(node.content):14,} {node.name}", "", self.current_dir
            
        files, err = self.fs.list_dir(target, self.current_user)
        if err:
            return "", err, self.current_dir
            
        output = f" Directory of {target}\n\n"
        d_c, f_c, t_s = 0, 0, 0
        for f in files:
            date_str = "12/22/2026  07:00 PM"
            if f["is_dir"]:
                output += f"{date_str}    <DIR>          {f['name']}\n"
                d_c += 1
            else:
                output += f"{date_str}    {f['size']:14,} {f['name']}\n"
                f_c += 1
                t_s += f["size"]
        output += f"               {f_c} File(s)     {t_s:,} bytes\n               {d_c} Dir(s)"
        return output, "", self.current_dir

    def _win_type(self, args):
        if not args:
            return "", "The syntax of the command is incorrect.", self.current_dir
        target = args[0]
        if not target.upper().startswith("C:"):
            target = self.current_dir + "\\" + target
        content, err = self.fs.read_file(target, self.current_user)
        if err:
            return "", err, self.current_dir
        return content, "", self.current_dir

    def _win_echo(self, cmd_line):
        match = re.search(r'echo\s+(.*?)\s*(>>|>)\s*(.*)', cmd_line, re.IGNORECASE)
        if not match:
            return cmd_line[5:].strip(), "", self.current_dir
            
        text = match.group(1).strip()
        mode = match.group(2)
        target = match.group(3).strip().strip('"')
        
        if not target.upper().startswith("C:"):
            target = self.current_dir + "\\" + target
        target = self.fs._normalize_path(target)
        
        existing = ""
        if mode == ">>" and self.fs.exists(target):
            content, err = self.fs.read_file(target, self.current_user)
            if not err:
                existing = content + "\n"
                
        success, err = self.fs.write_file(target, existing + text, self.current_user)
        if not success:
            return "", err, self.current_dir
        return "", "", self.current_dir

    def _win_mkdir(self, args):
        if not args:
            return "", "The syntax of the command is incorrect.", self.current_dir
        target = args[0]
        if not target.upper().startswith("C:"):
            target = self.current_dir + "\\" + target
        success, err = self.fs.mkdir(target, self.current_user)
        if not success:
            return "", err, self.current_dir
        return "", "", self.current_dir

    def _win_del(self, args):
        if not args:
            return "", "The syntax of the command is incorrect.", self.current_dir
        target = args[0]
        if not target.upper().startswith("C:"):
            target = self.current_dir + "\\" + target
        success, err = self.fs.delete_file(target, self.current_user)
        if not success:
            return "", err, self.current_dir
        return "", "", self.current_dir

    def _win_icacls(self, args):
        if not args:
            return "", "The syntax is incorrect.", self.current_dir
        target = args[0]
        if not target.upper().startswith("C:"):
            target = self.current_dir + "\\" + target
        target = self.fs._normalize_path(target)
        if not self.fs.exists(target):
            return "", "The system cannot find the file specified.", self.current_dir
        return self.fs.get_icacls_string(target) + "\nSuccessfully processed 1 files.", "", self.current_dir

    def _win_sc(self, args, cmd_line):
        if not args:
            return "SC Utility.", "", self.current_dir
        sub = args[0].lower()
        if sub == "query":
            if len(args) > 1:
                name = args[1]
                if name in self.services:
                    svc = self.services[name]
                    return f"SERVICE_NAME: {svc['name']}\n        TYPE               : {svc['type']}\n        STATE              : 4  {svc['status']}", "", self.current_dir
                return "", "Service does not exist.", self.current_dir
            # Print all
            out = ""
            for s in self.services.values():
                out += f"SERVICE_NAME: {s['name']}\nSTATE: {s['status']}\n\n"
            return out, "", self.current_dir
            
        elif sub == "qc":
            if len(args) > 1:
                name = args[1]
                if name in self.services:
                    svc = self.services[name]
                    return f"SERVICE_NAME: {svc['name']}\n        BINARY_PATH_NAME   : {svc['path']}\n        SERVICE_START_NAME : {svc['user']}", "", self.current_dir
                return "", "Service does not exist.", self.current_dir
                
        elif sub == "config":
            if len(args) >= 3:
                name = args[1]
                if name == "WeakService":
                    match = re.search(r'binPath=\s*"(.*?)"', cmd_line, re.IGNORECASE)
                    if not match:
                        match = re.search(r'binPath=\s*([^\s]+)', cmd_line, re.IGNORECASE)
                    if match:
                        bp_val = match.group(1)
                        self.services["WeakService"]["path"] = bp_val
                        return "[SC] ChangeServiceConfig SUCCESS", "", self.current_dir
                    else:
                        return "", "[SC] ChangeServiceConfig FAILED", self.current_dir
                else:
                    return "", "Access is denied.", self.current_dir
                    
        elif sub == "start":
            if len(args) > 1:
                name = args[1]
                if name in self.services:
                    svc = self.services[name]
                    svc["status"] = "RUNNING"
                    # Trigger checking
                    triggered, msg = self._eval_win_service(name)
                    if triggered:
                        return msg, "", self.current_dir
                    return f"Service {name} started.", "", self.current_dir
                return "", "Service not found.", self.current_dir
        return "", "Invalid sc operation", self.current_dir

    def _win_reg(self, args):
        if not args:
            return "REG Tool", "", self.current_dir
        sub = args[0].lower()
        if sub == "query":
            if len(args) > 1:
                key = args[1].upper().replace("HKLM", "HKEY_LOCAL_MACHINE").replace("HKCU", "HKEY_CURRENT_USER")
                matches = {k.upper().replace("HKLM", "HKEY_LOCAL_MACHINE").replace("HKCU", "HKEY_CURRENT_USER"): v for k, v in self.registry.items()}
                
                # Check direct or subkey match
                matched_outputs = []
                for k, v in matches.items():
                    if k.startswith(key):
                        matched_outputs.append(f"    {k.split('\\')[-1]}    REG_DWORD    0x{v:x}")
                        
                if not matched_outputs:
                    # Check service register mock for Lab 9
                    if "REGSERVICE" in key:
                        val = self.registry.get("HKLM\\System\\CurrentControlSet\\Services\\RegService\\ImagePath", "")
                        return f"\n{key}\n    ImagePath    REG_EXPAND_SZ    {val}", "", self.current_dir
                    return "", "ERROR: The system was unable to find the specified registry key or value.", self.current_dir
                    
                return f"\n{key}\n" + "\n".join(matched_outputs), "", self.current_dir
                
        elif sub == "add":
            # reg add <key> /v <name> /t <type> /d <data> /f
            if len(args) > 1:
                key = args[1].upper()
                v_name = ""
                d_val = ""
                try:
                    v_idx = [x.lower() for x in args].index("/v")
                    v_name = args[v_idx + 1]
                except ValueError:
                    pass
                try:
                    d_idx = [x.lower() for x in args].index("/d")
                    d_val = args[d_idx + 1]
                except ValueError:
                    pass
                    
                full_key = f"{key}\\{v_name}"
                # Handle Lab 9: Service registry overwrite
                if "REGSERVICE" in key and v_name.lower() == "imagepath":
                    self.registry["HKLM\\System\\CurrentControlSet\\Services\\RegService\\ImagePath"] = d_val
                    return "The operation completed successfully.", "", self.current_dir
                # Handle Lab 11: UAC Bypass Registry key addition
                elif "CLASSES\\MS-SETTINGS" in key:
                    self.registry["HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\"] = d_val
                    return "The operation completed successfully.", "", self.current_dir
                    
                self.registry[full_key] = d_val
                return "The operation completed successfully.", "", self.current_dir
                
        return "", "Invalid registry operation", self.current_dir

    def _win_net(self, args):
        if not args:
            return "NET command.", "", self.current_dir
        sub = args[0].lower()
        if sub == "localgroup":
            if len(args) > 1 and args[1].lower() == "administrators":
                if len(args) > 2:
                    usr = args[2]
                    action = args[3].lower() if len(args) > 3 else ""
                    if action == "/add":
                        if "Administrators" in self.groups or self.current_user in ["SYSTEM", "Administrator"]:
                            self.groups.append("Administrators")
                            # Verify Lab 2 status if they did it manually
                            if self.scenario_id == 2:
                                self._trigger_escalation(2)
                            return "The command completed successfully.", "", self.current_dir
                        return "", "Access is denied.", self.current_dir
                # List
                out = "Alias name     administrators\nMembers:\nAdministrator\n"
                if "Administrators" in self.groups:
                    out += f"{self.current_user}\n"
                return out + "The command completed successfully.", "", self.current_dir
        return "Command completed.", "", self.current_dir

    def _win_msiexec(self, args):
        t_path = None
        for idx, arg in enumerate(args):
            if arg.lower() == "/i" and idx + 1 < len(args):
                t_path = args[idx + 1]
                break
        if not t_path:
            return "msiexec /i <file>", "", self.current_dir
        if not t_path.upper().startswith("C:"):
            t_path = self.current_dir + "\\" + t_path
        t_path = self.fs._normalize_path(t_path)
        if not self.fs.exists(t_path):
            return "", "File not found.", self.current_dir
            
        hklm = self.registry.get("HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated", 0)
        hkcu = self.registry.get("HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated", 0)
        if hklm == 1 and hkcu == 1:
            self._trigger_escalation(3)
            return "Executing MSI package as SYSTEM...\nUpgraded session shell to SYSTEM!", "", self.current_dir
        return "Installation completed as regular user.", "", self.current_dir

    def _win_printspoofer(self, args):
        if "SeImpersonatePrivilege" in [p["name"] for p in self.privileges]:
            self._trigger_escalation(4)
            return "[+] Impersonated SYSTEM token successfully!\nSpawning SYSTEM cmd shell...", "", self.current_dir
        return "", "PrintSpoofer FAILED: Privilege not found.", self.current_dir

    def _win_juicypotato(self, args):
        if "SeImpersonatePrivilege" in [p["name"] for p in self.privileges]:
            self._trigger_escalation(4)
            return "[+] JuicyPotato execution OK!\nSpawning SYSTEM cmd shell...", "", self.current_dir
        return "", "JuicyPotato FAILED: Privilege not found.", self.current_dir

    def _win_cmdkey(self, args):
        if not args:
            return "CMDKEY: Command line tool to manage stored credentials.", "", self.current_dir
        sub = args[0].lower()
        if sub == "/list":
            return "\nCurrently stored credentials:\n\n    Target: Domain:target=WIN10-TARGET-01\n    Type: Domain Password\n    User: WIN10-TARGET-01\\Administrator\n", "", self.current_dir
        return "", "Invalid cmdkey switch", self.current_dir

    def _win_runas(self, args):
        # runas /user:Administrator /savecred "cmd.exe"
        user_val = None
        savecred = False
        cmd_run = ""
        for idx, arg in enumerate(args):
            if arg.lower().startswith("/user:"):
                user_val = arg[6:]
            elif arg.lower() == "/savecred":
                savecred = True
            else:
                cmd_run = arg
                
        if user_val and "administrator" in user_val.lower() and savecred:
            if self.scenario_id == 12:
                self._trigger_escalation(12)
                return f"Running as WIN10-TARGET-01\\Administrator...\nCredentials loaded from credential manager.\nCommand output:\nWIN10-TARGET-01\\Administrator logged in.", "", self.current_dir
        return "", "Attempting to launch... RUNAS FAILED: Enter password:", self.current_dir

    def _win_fodhelper(self):
        # Check if HKCU Software\Classes\ms-settings\shell\open\command is configured
        bypass_cmd = self.registry.get("HKCU\\Software\\Classes\\ms-settings\\shell\\open\command\\", None)
        if bypass_cmd:
            if self.scenario_id == 11:
                self._trigger_escalation(11)
                return f"Executing fodhelper.exe...\nDetecting high integrity auto-elevation bypass.\nExecuting registry hijack payload: {bypass_cmd}\nUpgraded shell session to SYSTEM!", "", self.current_dir
        return "Executing fodhelper.exe...\n[Features Page Loaded]", "", self.current_dir

    def _win_run_app(self):
        if self.scenario_id == 7:
            # Check if tpsapi.dll exists in labuser's Documents
            dll_path = "C:\\Users\\labuser\\Documents\\tpsapi.dll"
            if self.fs.exists(dll_path):
                self._trigger_escalation(7)
                return f"Running C:\\Program Files\\App\\app.exe...\nLoading dependencies...\nFound local relative DLL: C:\\Users\\labuser\\Documents\\tpsapi.dll\nExecuting DLL constructor code...\nShell upgraded to SYSTEM!", "", self.current_dir
            return "Running C:\\Program Files\\App\\app.exe...\n[Application running normally]", "", self.current_dir
        return "app.exe executed.", "", self.current_dir

    def _win_run_script(self):
        if self.scenario_id == 8:
            # Check if Temp contains netstat.exe
            netstat_payload = "C:\\Users\\labuser\\AppData\\Local\\Temp\\netstat.exe"
            if self.fs.exists(netstat_payload):
                self._trigger_escalation(8)
                return f"Executing run_script.bat...\nExecuting script lines:\n> netstat -ano\nFound hijacked netstat executable in local path priority: {netstat_payload}\nExecuting netstat.exe as SYSTEM...\nUpgraded shell to SYSTEM!", "", self.current_dir
            return "Executing run_script.bat...\nActive Connections:\n  Proto  Local Address          Foreign Address        State\n  TCP    0.0.0.0:5000           0.0.0.0:0              LISTENING", "", self.current_dir
        return "run_script.bat completed.", "", self.current_dir

    def _trigger_lab_5_exploit(self):
        # Lab 5: Autorun Executable Overwritten
        if self.fs.exists("C:\\Program Files\\Security Agent\\agent.exe"):
            self._trigger_escalation(5)
            return "Simulating Administrator login session...\nLaunching startup applications...\nExecuting C:\\Program Files\\Security Agent\\agent.exe as SYSTEM...\nExploit payload executed! Upgraded shell to SYSTEM.", "", self.current_dir
        return "Agent binary missing.", "", self.current_dir

    def _eval_win_service(self, service_name):
        if service_name == "VulnService":
            # Lab 1
            vuln_exe = "C:\\Program Files\\Vulnerable.exe"
            if self.fs.exists(vuln_exe):
                self._trigger_escalation(1)
                return True, "Attempting to start VulnService...\nService Manager executed C:\\Program Files\\Vulnerable.exe instead!\nUpgraded session to SYSTEM!"
        elif service_name == "WeakService":
            # Lab 2
            bin_path = self.services["WeakService"]["path"]
            if "net" in bin_path.lower() and "administrators" in bin_path.lower() and "/add" in bin_path.lower():
                self.groups.append("Administrators")
                self._trigger_escalation(2)
                return True, "Starting WeakService...\nExecuting: net localgroup administrators labuser /add\nUser added to Administrators successfully."
            elif "exploit" in bin_path.lower() or "shell" in bin_path.lower() or "cmd" in bin_path.lower() or bin_path.strip().startswith("C:\\Users\\labuser"):
                self._trigger_escalation(2)
                return True, f"Starting WeakService...\nExecuting configured path payload: {bin_path}\nUpgraded shell session to SYSTEM!"
        elif service_name == "WeakACLService":
            # Lab 6
            if self.fs.exists("C:\\Program Files\\WeakACL\\service.exe"):
                # If they wrote payload to service.exe
                content, _ = self.fs.read_file("C:\\Program Files\\WeakACL\\service.exe", "labuser")
                if content and "exploit" in content.lower() or "payload" in content.lower() or len(content) > 100:
                    self._trigger_escalation(6)
                    return True, "Starting WeakACLService...\nExecuting overwritten service binary C:\\Program Files\\WeakACL\\service.exe as SYSTEM...\nUpgraded shell session to SYSTEM!"
        elif service_name == "RegService":
            # Lab 9
            val = self.registry.get("HKLM\\System\\CurrentControlSet\\Services\\RegService\\ImagePath", "")
            if val and "net" in val.lower() and "administrators" in val.lower() and "/add" in val.lower():
                self.groups.append("Administrators")
                self._trigger_escalation(9)
                return True, f"Starting RegService...\nService manager executing configured ImagePath registry command: {val}\nUser added to Administrators group."
            elif val and ("exploit" in val.lower() or "payload" in val.lower() or val.strip().startswith("C:\\Users\\labuser")):
                self._trigger_escalation(9)
                return True, f"Starting RegService...\nExecuting payload registry path: {val}\nUpgraded shell to SYSTEM!"
        return False, ""

    def _trigger_escalation(self, scenario_id):
        self.escalated = True
        self.current_user = "SYSTEM" if self.os == "Windows" else "root"
        self.groups = ["SYSTEM", "Administrators", "Users"] if self.os == "Windows" else ["root", "student"]
        
        # Write Flag
        scenario = SCENARIOS.get(scenario_id)
        if scenario:
            if self.os == "Windows":
                self.current_dir = "C:\\Users\\Administrator\\Desktop"
                self.fs.write_file("C:\\Users\\Administrator\\Desktop\\flag.txt", f"CONGRATULATIONS!\nHere is your RootTheBox flag:\n{scenario.flag}", "SYSTEM")
            else:
                self.current_dir = "/root"
                self.fs.write_file("C:\\root\\flag.txt", f"CONGRATULATIONS!\nHere is your RootTheBox flag:\n{scenario.flag}", "root")

    def _win_help(self):
        return """RootTheBox Windows Lab Command List:
    whoami, whoami /priv, whoami /groups
    cd, dir, type, echo, mkdir, del, icacls
    sc <query/qc/config/start>
    reg <query/add>
    net localgroup administrators [/add]
    msiexec /i <installer.msi>
    cmdkey /list
    runas /user:Administrator /savecred <cmd>
    fodhelper.exe (runs UAC bypass utility)
    help
""", "", self.current_dir

    # ==========================================
    # LINUX COMMAND ROUTER
    # ==========================================
    def _execute_linux(self, cmd_line):
        # Parse command tokens (handling pipes or simple commands)
        # Note: Linux redirect handling can be simulated like Windows echo
        tokens = re.findall(r'(?:[^\s"]+|"[^"]*")+', cmd_line)
        if not tokens:
            return "", "", self.current_dir
            
        args = [t.strip('"') for t in tokens]
        cmd = args[0]
        
        if cmd == "whoami":
            return self.current_user, "", self.current_dir
        elif cmd == "id":
            uid_str = "0(root)" if self.current_user == "root" else "1000(student)"
            gid_str = "0(root)" if self.current_user == "root" else "1000(student)"
            grps_str = ",".join([f"1000({g})" if g != "root" and g != "docker" else ("0(root)" if g == "root" else "999(docker)") for g in self.groups])
            return f"uid={uid_str} gid={gid_str} groups={grps_str}", "", self.current_dir
        elif cmd == "cd":
            return self._lnx_cd(args[1:])
        elif cmd in ["ls", "dir"]:
            return self._lnx_ls(args[1:])
        elif cmd in ["cat", "type"]:
            return self._lnx_cat(args[1:])
        elif cmd == "echo":
            return self._lnx_echo(cmd_line)
        elif cmd == "mkdir":
            return self._lnx_mkdir(args[1:])
        elif cmd in ["rm", "del"]:
            return self._lnx_rm(args[1:])
        elif cmd == "sudo":
            return self._lnx_sudo(args[1:])
        elif cmd == "su":
            return self._lnx_su(args[1:])
        elif cmd == "tar":
            return self._lnx_tar(args[1:])
        elif cmd == "chmod":
            return self._lnx_chmod(args[1:])
        elif cmd == "python3" or cmd == "python":
            return self._lnx_python(args[1:])
        elif cmd == "docker":
            return self._lnx_docker(args[1:])
        elif cmd == "export":
            # e.g. export PATH=/tmp:$PATH
            if len(args) > 1 and "path" in args[1].lower():
                val = args[1].split("=")[-1]
                self.linux_path = val.replace("$PATH", self.linux_path)
                return "", "", self.current_dir
            return f"PATH={self.linux_path}", "", self.current_dir
        elif cmd == "help":
            return self._lnx_help()
        else:
            # Check SUID ELF executable run (e.g. /usr/local/bin/system_status or calc)
            resolved_exe = None
            if cmd.startswith("./"):
                resolved_exe = self.to_win_path(cmd[2:])
            elif cmd.startswith("/"):
                resolved_exe = self.to_win_path(cmd)
            else:
                # Naked command: search in linux PATH
                for p in self.linux_path.split(":"):
                    test_path = p + "/" + cmd
                    win_test = self.to_win_path(test_path)
                    if self.fs.exists(win_test):
                        resolved_exe = win_test
                        break
                if not resolved_exe:
                    resolved_exe = self.to_win_path(cmd)
                    
            if resolved_exe and self.fs.exists(resolved_exe):
                if "system_status" in resolved_exe.lower():
                    return self._lnx_run_system_status()
                elif "calc" in resolved_exe.lower():
                    return self._lnx_run_calc()
                return f"Running script/binary: {cmd}\n[Execution complete]", "", self.current_dir
                
            return "", f"bash: {cmd}: command not found", self.current_dir

    def _lnx_cd(self, args):
        if not args:
            self.current_dir = "/root" if self.current_user == "root" else "/home/student"
            return "", "", self.current_dir
            
        target = args[0]
        # Translate target unix to win path
        win_path = self.to_win_path(target)
        if not self.fs.exists(win_path):
            return "", f"cd: {target}: No such file or directory", self.current_dir
        if not self.fs.is_dir(win_path):
            return "", f"cd: {target}: Not a directory", self.current_dir
            
        node = self.fs._get_node(win_path)
        if not self.fs.has_read_permission(node, self.current_user):
            return "", "Permission denied", self.current_dir
            
        self.current_dir = self.to_unix_path(win_path)
        return "", "", self.current_dir

    def _lnx_ls(self, args):
        target_dir = self.current_dir
        if args and not args[0].startswith("-"):
            target_dir = args[0]
            
        win_path = self.to_win_path(target_dir)
        if not self.fs.exists(win_path):
            return "", f"ls: cannot access '{target_dir}': No such file or directory", self.current_dir
            
        if not self.fs.is_dir(win_path):
            # Print file details
            node = self.fs._get_node(win_path)
            # Check SUID mock printout
            perm_str = "-rwsr-xr-x" if "system_status" in node.name or "calc" in node.name else "-rw-r--r--"
            return f"{perm_str} 1 {node.owner} group {len(node.content)} Dec 22 {node.name}", "", self.current_dir
            
        files, err = self.fs.list_dir(win_path, self.current_user)
        if err:
            return "", "ls: Permission denied", self.current_dir
            
        # Format output
        output_lines = []
        for f in files:
            p_str = "drwxr-xr-x" if f["is_dir"] else "-rw-r--r--"
            # SUID checks
            if f["name"] in ["system_status", "calc"]:
                p_str = "-rwsr-xr-x"
            output_lines.append(f"{p_str} 1 {f['owner']} {f['owner']} {f['size']:6} Dec 22 {f['name']}")
        return "\n".join(output_lines), "", self.current_dir

    def _lnx_cat(self, args):
        if not args:
            return "", "cat: missing file operand", self.current_dir
        target = args[0]
        win_path = self.to_win_path(target)
        content, err = self.fs.read_file(win_path, self.current_user)
        if err:
            # Map error message to linux style
            if "denied" in err.lower():
                return "", "cat: Permission denied", self.current_dir
            return "", f"cat: {target}: No such file or directory", self.current_dir
        return content, "", self.current_dir

    def _lnx_echo(self, cmd_line):
        match = re.search(r'echo\s+(.*?)\s*(>>|>)\s*(.*)', cmd_line)
        if not match:
            return cmd_line[5:].strip().strip('"'), "", self.current_dir
            
        text = match.group(1).strip().strip('"')
        mode = match.group(2)
        target = match.group(3).strip().strip('"')
        
        win_path = self.to_win_path(target)
        
        existing = ""
        if mode == ">>" and self.fs.exists(win_path):
            content, err = self.fs.read_file(win_path, self.current_user)
            if not err:
                existing = content + "\n"
                
        # Lab 15 helper check: editing passwd
        if "passwd" in win_path.lower():
            # Check user input
            pass
            
        success, err = self.fs.write_file(win_path, existing + text, self.current_user)
        if not success:
            return "", "echo: write error: Permission denied", self.current_dir
            
        # Trigger Lab 18 check if backup.sh was overwritten
        if self.scenario_id == 18 and "backup.sh" in win_path.lower():
            self._trigger_lnx_cron_18()
            
        # Trigger Lab 19 check if cron payload was written
        if self.scenario_id == 19 and "exploit.sh" in win_path.lower():
            self._trigger_lnx_cron_19()
            
        return "", "", self.current_dir

    def _lnx_mkdir(self, args):
        if not args:
            return "", "mkdir: missing operand", self.current_dir
        target = args[0]
        win_path = self.to_win_path(target)
        success, err = self.fs.mkdir(win_path, self.current_user)
        if not success:
            return "", "mkdir: cannot create directory: Permission denied", self.current_dir
        return "", "", self.current_dir

    def _lnx_rm(self, args):
        if not args:
            return "", "rm: missing operand", self.current_dir
        target = args[0]
        win_path = self.to_win_path(target)
        success, err = self.fs.delete_file(win_path, self.current_user)
        if not success:
            return "", "rm: cannot remove: Permission denied", self.current_dir
        return "", "", self.current_dir

    def _lnx_sudo(self, args):
        if not args:
            return "sudo: a password is required", "", self.current_dir
        sub = args[0]
        if sub == "-l":
            # List permissions
            if self.scenario_id == 16:
                return "Matching Defaults entries for student on rootthebox:\n    env_reset, mail_badpass\n\nUser student may run the following commands on rootthebox:\n    (root) NOPASSWD: /usr/bin/find", "", self.current_dir
            elif self.scenario_id == 17:
                return "User student may run the following commands:\n    (root) NOPASSWD: /usr/bin/less, /usr/bin/vi", "", self.current_dir
            elif self.scenario_id == 22:
                return "Matching Defaults entries:\n    env_keep+=LD_PRELOAD\n\nUser student may run the following commands:\n    (root) NOPASSWD: /usr/sbin/apache2", "", self.current_dir
            return "User student is not allowed to run sudo on rootthebox.", "", self.current_dir
            
        # Running command with sudo privileges
        # Lab 16: sudo find . -exec /bin/sh \;
        if sub == "find" or sub == "/usr/bin/find":
            if self.scenario_id == 16 and any("-exec" in a for a in args):
                self._trigger_escalation(16)
                return "Executing find with root privileges...\nSpawning root shell...", "", self.current_dir
                
        elif sub in ["less", "/usr/bin/less", "vi", "/usr/bin/vi"]:
            if self.scenario_id == 17:
                if len(args) > 1 and args[1] in ["!/bin/sh", "!sh", ":!sh"]:
                    self._trigger_escalation(17)
                    return "Editor shell escape triggered!\nUpgraded shell session to root!", "", self.current_dir
                # Prompt user for shell escape
                return "Entering editor context...\n[Type '!/bin/sh' or ':!sh' inside this interactive terminal session to drop to shell]", "", self.current_dir
                
        # Lab 22: sudo LD_PRELOAD=/tmp/exploit.so apache2
        # Check if LD_PRELOAD parameter was provided
        ld_preload_path = None
        for a in args:
            if a.startswith("LD_PRELOAD="):
                ld_preload_path = a.split("=")[-1]
                
        if ld_preload_path and self.scenario_id == 22:
            win_preload = self.to_win_path(ld_preload_path)
            if self.fs.exists(win_preload):
                self._trigger_escalation(22)
                return f"[+] Found LD_PRELOAD={ld_preload_path}\n[+] Shared object loaded successfully.\n[+] Constructor payload executed with root permissions.\nSpawning root shell...", "", self.current_dir
                
        # Check vi/less shell escapes manually
        # E.g. sudo vi then inside they run '!sh'
        if len(args) > 1 and args[1] in ["!/bin/sh", "!sh", ":!sh"]:
            if self.scenario_id == 17:
                self._trigger_escalation(17)
                return "Editor shell escape triggered!\nUpgraded shell session to root!", "", self.current_dir
                
        return f"sudo: permission denied for command: {sub}", "", self.current_dir

    def _lnx_su(self, args):
        if not args:
            return "su: Password required", "", self.current_dir
        target_usr = args[0]
        # Password check
        pwd_input = args[1] if len(args) > 1 else ""
        
        # Lab 15: Writable passwd
        # If user wrote hacker:x:0:0...
        if target_usr == "hacker" and self.scenario_id == 15:
            # Check if passwd has hacker
            content, _ = self.fs.read_file("C:\\etc\\passwd", "student")
            if content and "hacker" in content:
                self._trigger_escalation(15)
                return "Authenticating...\nLogged in as hacker.\nUpgraded shell session to root!", "", self.current_dir
                
        # Lab 20: shadow cracking
        if target_usr == "root" and self.scenario_id == 20:
            if pwd_input == "rootpassword" or pwd_input == "password":
                self._trigger_escalation(20)
                return "Authenticating...\nLogged in as root.\nUpgraded shell session to root!", "", self.current_dir
            return "su: Authentication failure", "", self.current_dir
            
        return f"su: user {target_usr} does not exist", "", self.current_dir

    def _lnx_tar(self, args):
        # Lab 19 wildcard check
        # E.g. student writes filenames --checkpoint=1 and --checkpoint-action=exec=sh exploit.sh
        # If they execute tar -cf backup.tar *
        if self.scenario_id == 19:
            # Check if files exist inside /var/www/html
            f1 = self.fs.exists("C:\\var\\www\\html\\--checkpoint=1")
            f2 = self.fs.exists("C:\\var\\www\\html\\--checkpoint-action=exec=sh exploit.sh")
            f3 = self.fs.exists("C:\\var\\www\\html\\exploit.sh")
            if f1 and f2 and f3:
                self._trigger_escalation(19)
                return "tar: Expanding wildcards inside current directory...\nExecuting wildcard command parameter: --checkpoint-action=exec=sh exploit.sh\nRunning exploit.sh as root...\nUpgraded session to root!", "", self.current_dir
        return "tar: archive created successfully.", "", self.current_dir

    def _lnx_chmod(self, args):
        # Lab 24: chmod +s /mnt/share/shell
        if self.scenario_id == 24 and len(args) >= 2:
            mode = args[0]
            target = args[1]
            win_path = self.to_win_path(target)
            if "+s" in mode and "share" in win_path.lower() and self.fs.exists(win_path):
                self._trigger_escalation(24)
                return f"Setting permissions: {mode} on {target}...\n[+] SUID bit set on NFS share file.\n[+] Executing file from target client...\nUpgraded shell session to root!", "", self.current_dir
        return "", "", self.current_dir

    def _lnx_python(self, args):
        # Lab 21 SUID cap
        # python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
        code_str = ""
        for idx, arg in enumerate(args):
            if arg == "-c" and idx + 1 < len(args):
                code_str = args[idx + 1]
                
        if self.scenario_id == 21 and "setuid(0)" in code_str:
            self._trigger_escalation(21)
            return "Executing Python script with SETUID capabilities...\nUpgraded shell session to root!", "", self.current_dir
        return "Python interactive shell completed.", "", self.current_dir

    def _lnx_docker(self, args):
        # Lab 23: docker run -v /:/mnt -it alpine sh
        if self.scenario_id == 23 and "docker" in self.groups:
            # Check for volume mounting flag
            if any("-v" in a for a in args) and any("/:/mnt" in a or "/:/host" in a for a in args):
                self._trigger_escalation(23)
                return "Mounting host filesystem inside container...\nLogged in as container root. Full access to host disk at /mnt.\nUpgraded session to root!", "", self.current_dir
        return "", "docker: Permission denied. Accessing daemon socket failed.", self.current_dir

    def _lnx_run_system_status(self):
        # Lab 13 SUID path
        # Check PATH directories. If /tmp is before /usr/bin, it executes /tmp/service
        if "/tmp" in self.linux_path and self.linux_path.index("/tmp") < self.linux_path.index("/usr/bin"):
            # Check if /tmp/service exists
            fake_service = "C:\\tmp\\service"
            if self.fs.exists(fake_service):
                self._trigger_escalation(13)
                return "Executing SUID /usr/local/bin/system_status...\nExecuting subcommand: service apache2 status\nFound local relative command override in PATH: /tmp/service\nRunning /tmp/service as root...\nUpgraded shell to root!", "", self.current_dir
        return "Executing SUID /usr/local/bin/system_status...\nSystem status check:\n  Apache Service is inactive.", "", self.current_dir

    def _lnx_run_calc(self):
        # Lab 14 SO Injection
        # Check if libcalc.so exists in student libs
        lib_path = "C:\\home\\student\\libs\\libcalc.so"
        if self.fs.exists(lib_path):
            self._trigger_escalation(14)
            return "Executing /usr/local/bin/calc...\nLoading dynamic shared libraries...\nFound library: /home/student/libs/libcalc.so\nExecuting library constructor code as root...\nUpgraded shell session to root!", "", self.current_dir
        return "Executing /usr/local/bin/calc...\nResult: 0", "", self.current_dir

    def _trigger_lnx_cron_18(self):
        # Lab 18 Cron written
        # Verify content
        content, _ = self.fs.read_file("C:\\usr\\local\\bin\\backup.sh", "student")
        if content and len(content) > 10 and ("root" in content or "sh" in content or "exploit" in content or "flag" in content):
            self._trigger_escalation(18)

    def _trigger_lnx_cron_19(self):
        # Lab 19 cron exploit payload written
        # Verify
        pass

    def _lnx_help(self):
        return """RootTheBox Linux Lab Command List:
    whoami, id, hostname
    cd, ls, cat, echo, mkdir, rm, chmod
    sudo -l, sudo <cmd>
    su <user>
    tar -cf <archive> <files>
    python3 -c '<script>'
    docker run
    export PATH=<val>
    help
""", "", self.current_dir
