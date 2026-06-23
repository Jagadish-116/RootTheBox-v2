class LabScenario:
    def __init__(self, id, name, category, description, difficulty, initial_user, initial_dir, registry_defaults=None, flag=""):
        self.id = id
        self.name = name
        self.category = category # "Windows" or "Linux"
        self.description = description
        self.difficulty = difficulty
        self.initial_user = initial_user
        self.initial_dir = initial_dir
        self.registry_defaults = registry_defaults if registry_defaults else {}
        self.flag = flag

    def setup(self, fs, registry):
        # Reset registry to defaults
        registry.clear()
        for k, v in self.registry_defaults.items():
            registry[k] = v
            
        # Reset filesystem structure
        fs.__init__()
        
        # Scenario-specific customization
        setup_method_name = f"_setup_lab_{self.id}"
        if hasattr(self, setup_method_name):
            getattr(self, setup_method_name)(fs)

    # ==========================================
    # WINDOWS LABS SETUP (1 - 12)
    # ==========================================
    def _setup_lab_1(self, fs):
        # Lab 1: Unquoted Service Paths
        fs.mkdir("C:\\Program Files\\Vulnerable Software")
        prog_files = fs._get_node("C:\\Program Files")
        if prog_files:
            prog_files.writable_by = ["labuser", "Administrators", "SYSTEM"]
        fs.write_file("C:\\Program Files\\Vulnerable Software\\Vulnerable Service.exe", "[Binary Service Code]", "SYSTEM")
        fs.write_file("C:\\Users\\labuser\\Desktop\\notes.txt", "Task: Locate the service running with an unquoted path. Find where you can write a payload.", "labuser")

    def _setup_lab_2(self, fs):
        # Lab 2: Weak Service Permissions
        fs.mkdir("C:\\Program Files\\Weak Service")
        fs.write_file("C:\\Program Files\\Weak Service\\service.exe", "[Weak Service Binary]", "SYSTEM")
        fs.write_file("C:\\Users\\labuser\\Desktop\\hints.txt", "Use 'sc' to query configuration of 'WeakService'. Check modifying rights.", "labuser")

    def _setup_lab_3(self, fs):
        # Lab 3: AlwaysInstallElevated
        fs.write_file("C:\\Users\\labuser\\Desktop\\exploit.msi", "[Malicious Installer Payload]", "labuser")

    def _setup_lab_4(self, fs):
        # Lab 4: Token Impersonation
        fs.mkdir("C:\\inetpub")
        fs.mkdir("C:\\inetpub\\wwwroot")
        ls_docs = fs._get_node("C:\\Users\\labuser\\Documents")
        if ls_docs:
            ls_docs.writable_by.append("local service")
            ls_docs.readable_by.append("local service")
        fs.write_file("C:\\Users\\labuser\\Documents\\PrintSpoofer.exe", "[PrintSpoofer Impersonation Exploit]", "SYSTEM")

    def _setup_lab_5(self, fs):
        # Lab 5: Registry Autorun
        fs.mkdir("C:\\Program Files\\Security Agent")
        agent_dir = fs._get_node("C:\\Program Files\\Security Agent")
        if agent_dir:
            agent_dir.writable_by = ["labuser", "Administrators", "SYSTEM"]
        fs.write_file("C:\\Program Files\\Security Agent\\agent.exe", "[Security Monitor Binary]", "SYSTEM")
        fs.write_file("C:\\Users\\labuser\\Desktop\\notes.txt", "An administrator startup agent executable is loaded from a writable folder.", "labuser")

    def _setup_lab_6(self, fs):
        # Lab 6: Weak Service Executable ACLs
        fs.mkdir("C:\\Program Files\\WeakACL")
        acl_dir = fs._get_node("C:\\Program Files\\WeakACL")
        if acl_dir:
            acl_dir.writable_by = ["labuser", "Administrators", "SYSTEM"]
        fs.write_file("C:\\Program Files\\WeakACL\\service.exe", "[Vulnerable service executable file]", "SYSTEM")
        # Give everyone permissions to overwrite the file itself
        svc_file = fs._get_node("C:\\Program Files\\WeakACL\\service.exe")
        if svc_file:
            svc_file.writable_by = ["labuser", "Administrators", "SYSTEM"]

    def _setup_lab_7(self, fs):
        # Lab 7: DLL Hijacking
        fs.mkdir("C:\\Program Files\\App")
        fs.write_file("C:\\Program Files\\App\\app.exe", "[Main application binary loaded by Administrator]", "SYSTEM")
        fs.write_file("C:\\Users\\labuser\\Desktop\\readme.txt", "The system application 'app.exe' tries to load 'tpsapi.dll' relative to User Documents.", "labuser")

    def _setup_lab_8(self, fs):
        # Lab 8: PATH Environment Hijacking
        fs.mkdir("C:\\Users\\labuser\\AppData\\Local\\Temp")
        temp_dir = fs._get_node("C:\\Users\\labuser\\AppData\\Local\\Temp")
        if temp_dir:
            temp_dir.writable_by = ["labuser", "Administrators", "SYSTEM"]
        fs.write_file("C:\\Windows\\System32\\run_script.bat", "netstat -ano", "SYSTEM")

    def _setup_lab_9(self, fs):
        # Lab 9: Service Registry Overwrite
        # Registry key is set in defaults. Create the service target.
        fs.mkdir("C:\\Program Files\\RegService")
        fs.write_file("C:\\Program Files\\RegService\\service.exe", "[Registry Configured Service]", "SYSTEM")

    def _setup_lab_10(self, fs):
        # Lab 10: Modifiable Startup Shortcut
        fs.mkdir("C:\\Users\\labuser\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\Startup")
        startup_dir = fs._get_node("C:\\Users\\labuser\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        if startup_dir:
            startup_dir.writable_by = ["labuser", "Administrators", "SYSTEM"]
        fs.write_file("C:\\Users\\labuser\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\check.lnk", "[Shortcut pointing to C:\\Windows\\System32\\cmd.exe]", "labuser")

    def _setup_lab_11(self, fs):
        # Lab 11: UAC Bypass (Fodhelper)
        # Simply sets up information.
        fs.write_file("C:\\Users\\labuser\\Desktop\\notes.txt", "Target utility: C:\\Windows\\System32\\fodhelper.exe. Explore HKCU Software\\Classes\\ms-settings.", "labuser")

    def _setup_lab_12(self, fs):
        # Lab 12: Saved Credentials (cmdkey)
        # Set up a backup file on administrator desktop
        fs.write_file("C:\\Users\\Administrator\\Desktop\\backup.zip", "[Compressed administrator backup archive]", "SYSTEM")

    # ==========================================
    # LINUX LABS SETUP (13 - 24)
    # ==========================================
    def _setup_linux_dirs(self, fs):
        # Linux standard structure
        fs.mkdir("C:\\etc")
        fs.mkdir("C:\\etc\\cron.d")
        fs.mkdir("C:\\tmp")
        tmp_dir = fs._get_node("C:\\tmp")
        if tmp_dir:
            tmp_dir.writable_by = ["student", "Everyone", "root", "SYSTEM"]
        fs.mkdir("C:\\usr")
        fs.mkdir("C:\\usr\\bin")
        fs.mkdir("C:\\usr\\local")
        fs.mkdir("C:\\usr\\local\\bin")
        fs.mkdir("C:\\home")
        fs.mkdir("C:\\home\\student")
        fs.mkdir("C:\\root")
        
        # Modify permissions
        root_dir = fs._get_node("C:\\root")
        if root_dir:
            root_dir.readable_by = ["root", "SYSTEM"]
            root_dir.writable_by = ["root", "SYSTEM"]
            root_dir.owner = "root"
            
        student_dir = fs._get_node("C:\\home\\student")
        if student_dir:
            student_dir.readable_by = ["student", "root", "SYSTEM"]
            student_dir.writable_by = ["student", "root", "SYSTEM"]
            student_dir.owner = "student"

    def _setup_lab_13(self, fs):
        # Lab 13: SUID PATH Hijacking
        self._setup_linux_dirs(fs)
        fs.write_file("C:\\usr\\local\\bin\\system_status", "[SUID ELF Binary: Executes 'service apache2 status' relatively]", "root")
        suid_bin = fs._get_node("C:\\usr\\local\\bin\\system_status")
        if suid_bin:
            suid_bin.owner = "root"
            # Simulate SUID flag
            suid_bin.writable_by = ["root", "SYSTEM"]

    def _setup_lab_14(self, fs):
        # Lab 14: SUID Shared Object Injection
        self._setup_linux_dirs(fs)
        fs.mkdir("C:\\home\\student\\libs")
        libs_dir = fs._get_node("C:\\home\\student\\libs")
        if libs_dir:
            libs_dir.writable_by = ["student", "root", "SYSTEM"]
        fs.write_file("C:\\usr\\local\\bin\\calc", "[SUID ELF Binary: Attempts loading libcalc.so from /home/student/libs]", "root")

    def _setup_lab_15(self, fs):
        # Lab 15: Writable /etc/passwd
        self._setup_linux_dirs(fs)
        fs.write_file(
            "C:\\etc\\passwd",
            "root:x:0:0:root:/root:/bin/bash\nstudent:x:1000:1000:student:/home/student:/bin/bash",
            "root"
        )
        passwd = fs._get_node("C:\\etc\\passwd")
        if passwd:
            # Writable by everyone
            passwd.writable_by = ["student", "Everyone", "root", "SYSTEM"]

    def _setup_lab_16(self, fs):
        # Lab 16: Sudo Rights (find)
        self._setup_linux_dirs(fs)
        fs.write_file("C:\\usr\\bin\\find", "[Find Binary Utility]", "root")

    def _setup_lab_17(self, fs):
        # Lab 17: Sudo Rights (less/vi)
        self._setup_linux_dirs(fs)
        fs.write_file("C:\\usr\\bin\\less", "[Pager Less Utility]", "root")
        fs.write_file("C:\\usr\\bin\\vi", "[Vi Editor Utility]", "root")

    def _setup_lab_18(self, fs):
        # Lab 18: Writable Cron Job
        self._setup_linux_dirs(fs)
        fs.write_file("C:\\etc\\cron.d\\backup", "*/1 * * * * root /usr/local/bin/backup.sh", "root")
        fs.write_file("C:\\usr\\local\\bin\\backup.sh", "#!/bin/bash\ntar -czf /tmp/backup.tar.gz /home/student/documents", "root")
        
        # Make script writable by student
        script = fs._get_node("C:\\usr\\local\\bin\\backup.sh")
        if script:
            script.writable_by = ["student", "root", "SYSTEM"]

    def _setup_lab_19(self, fs):
        # Lab 19: Cron Wildcard Tar
        self._setup_linux_dirs(fs)
        fs.mkdir("C:\\var")
        fs.mkdir("C:\\var\\www")
        fs.mkdir("C:\\var\\www\\html")
        html_dir = fs._get_node("C:\\var\\www\\html")
        if html_dir:
            html_dir.writable_by = ["student", "root", "SYSTEM"]
        fs.write_file("C:\\etc\\cron.d\\compress", "*/1 * * * * root cd /var/www/html && tar -cf /backups/backup.tar *", "root")

    def _setup_lab_20(self, fs):
        # Lab 20: Readable /etc/shadow
        self._setup_linux_dirs(fs)
        fs.write_file(
            "C:\\etc\\shadow",
            "root:$6$4b2A5f!9$m1FqB90LpX9R2zTq8yK1p5wX9q8b7C...:19000:0:99999:7:::\nstudent:$6$stu123$abc:19000:0:99999:7:::",
            "root"
        )
        shadow = fs._get_node("C:\\etc\\shadow")
        if shadow:
            shadow.readable_by = ["student", "root", "SYSTEM"]

    def _setup_lab_21(self, fs):
        # Lab 21: Capabilities (Python)
        self._setup_linux_dirs(fs)
        fs.write_file("C:\\usr\\bin\\python3", "[Python Interpreter with cap_setuid+ep capability]", "root")

    def _setup_lab_22(self, fs):
        # Lab 22: Sudo LD_PRELOAD
        self._setup_linux_dirs(fs)

    def _setup_lab_23(self, fs):
        # Lab 23: Docker Socket
        self._setup_linux_dirs(fs)
        fs.write_file("C:\\var\\run\\docker.sock", "[Docker Daemon Socket]", "root")
        socket = fs._get_node("C:\\var\\run\\docker.sock")
        if socket:
            socket.readable_by = ["student", "root", "SYSTEM"]
            socket.writable_by = ["student", "root", "SYSTEM"]

    def _setup_lab_24(self, fs):
        # Lab 24: NFS Root Squashing
        self._setup_linux_dirs(fs)
        fs.mkdir("C:\\mnt")
        fs.mkdir("C:\\mnt\\share")
        share = fs._get_node("C:\\mnt\\share")
        if share:
            share.writable_by = ["student", "Everyone", "root", "SYSTEM"]


# Scenario declarations
SCENARIOS = {
    # WINDOWS (1 - 12)
    1: LabScenario(
        id=1, name="Unquoted Service Paths", category="Windows",
        description="Exploit service paths missing quotation marks by hijacking spaces.",
        difficulty="Easy", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{U_NQu0t3d_P@th_ExPl01t_9a8B7c!}"
    ),
    2: LabScenario(
        id=2, name="Weak Service Permissions", category="Windows",
        description="Change a service config binary path to run elevated commands.",
        difficulty="Medium", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{W3aK_Svc_C0nf1g_EscaL4t3_#f1d2e3}"
    ),
    3: LabScenario(
        id=3, name="AlwaysInstallElevated", category="Windows",
        description="Abuse registry settings that permit elevated installer executions.",
        difficulty="Easy", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        registry_defaults={
            "HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated": 1,
            "HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated": 1
        },
        flag="FLAG{Alw4ys_Inst@ll_El3v4t3d_M5i_99#88}"
    ),
    4: LabScenario(
        id=4, name="Token Impersonation (PrintSpoofer)", category="Windows",
        description="Abuse SeImpersonatePrivilege to impersonate SYSTEM accounts.",
        difficulty="Hard", initial_user="local service", initial_dir="C:\\Users\\labuser\\Documents",
        flag="FLAG{T0k3n_Imp3rs0n4ti0n_Sp00f_!77a}"
    ),
    5: LabScenario(
        id=5, name="Insecure Registry Autorun", category="Windows",
        description="Hijack an administrative startup program written in registry run keys.",
        difficulty="Easy", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{R3g1stry_Aut0run_H1j4ck_#8a9b2C}"
    ),
    6: LabScenario(
        id=6, name="Weak Service Executable ACLs", category="Windows",
        description="Directly replace a service executable program on disk due to weak ACLs.",
        difficulty="Medium", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{W3ak_Svc_Bin_Wr1t3_77#2b!}"
    ),
    7: LabScenario(
        id=7, name="DLL Hijacking", category="Windows",
        description="Hijack a missing application DLL using search path order.",
        difficulty="Medium", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{Dll_H1j4ck_L0ad_Succ3ss_#f9a2}"
    ),
    8: LabScenario(
        id=8, name="PATH Environment Hijacking", category="Windows",
        description="Abuse writable directories listed early in the PATH variable.",
        difficulty="Medium", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{P4th_Env_Var_H1j4ck_@982b}"
    ),
    9: LabScenario(
        id=9, name="Service Registry Overwrite", category="Windows",
        description="Overwrite service config registry keys directly to change binary path.",
        difficulty="Hard", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        registry_defaults={
            "HKLM\\System\\CurrentControlSet\Services\\RegService\\ImagePath": "C:\\Program Files\\RegService\\service.exe"
        },
        flag="FLAG{Svc_R3g1stry_Ov3rwr1te_!33c1}"
    ),
    10: LabScenario(
        id=10, name="Modifiable Startup Shortcut", category="Windows",
        description="Create or overwrite shortcut scripts in the Windows Startup folder.",
        difficulty="Easy", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{St4rtup_Lnk_Ov3rwrit3_#f2f3}"
    ),
    11: LabScenario(
        id=11, name="UAC Bypass (Fodhelper)", category="Windows",
        description="Bypass User Account Control using Registry Hijacks inside Fodhelper.",
        difficulty="Hard", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{Uac_Byp4ss_F0dhlpr_!88a2b}"
    ),
    12: LabScenario(
        id=12, name="Saved Credentials (cmdkey)", category="Windows",
        description="Exploit credentials stored in the Windows vault to run as Admin.",
        difficulty="Medium", initial_user="labuser", initial_dir="C:\\Users\\labuser",
        flag="FLAG{Sav3d_Cr3ds_Cmdk3y_@a1b2c}"
    ),
    
    # LINUX (13 - 24)
    13: LabScenario(
        id=13, name="SUID PATH Hijacking", category="Linux",
        description="Exploit an SUID binary that calls commands without absolute paths.",
        difficulty="Easy", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Su1d_P4th_H1j4ck_R00t_#8a9b}"
    ),
    14: LabScenario(
        id=14, name="SUID Shared Object Injection", category="Linux",
        description="Inject a malicious shared library into an SUID search path.",
        difficulty="Medium", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Su1d_So_Inject1on_Succ3ss_!f2}"
    ),
    15: LabScenario(
        id=15, name="Writable /etc/passwd", category="Linux",
        description="Append a root-equivalent user entry directly to /etc/passwd.",
        difficulty="Easy", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Writ4bl3_Etc_Passwd_Root_@99a}"
    ),
    16: LabScenario(
        id=16, name="Sudo Rights (find)", category="Linux",
        description="Abuse find wildcard system executes running under sudo configuration.",
        difficulty="Easy", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Sudo_F1nd_Esc4p3_R00t_#c1d2}"
    ),
    17: LabScenario(
        id=17, name="Sudo Rights (less/vi)", category="Linux",
        description="Abuse interactive pagers running with elevated privileges.",
        difficulty="Easy", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Sudo_L3ss_V1_Sh3ll_!99b8}"
    ),
    18: LabScenario(
        id=18, name="Writable Cron Job Script", category="Linux",
        description="Overwrite a backup script executed on schedule as root.",
        difficulty="Medium", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Cr0n_J0b_Script_Ov3rwrit3_@7a}"
    ),
    19: LabScenario(
        id=19, name="Cron Wildcard Tar Injection", category="Linux",
        description="Abuse command arguments in backup files using wildcard parameters.",
        difficulty="Hard", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{T4r_W1ldc4rd_Explo1t_99#11}"
    ),
    20: LabScenario(
        id=20, name="Readable /etc/shadow", category="Linux",
        description="Crack the root shadow hash to authenticate via su privileges.",
        difficulty="Medium", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Etc_Sh4d0w_R3ad_Acc3ss_!f8a}"
    ),
    21: LabScenario(
        id=21, name="Linux Capabilities (Python)", category="Linux",
        description="Hijack Python with SETUID capabilities to set root credentials.",
        difficulty="Medium", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Cap4bilit1es_Pyth0n_Setu1d_#22}"
    ),
    22: LabScenario(
        id=22, name="Sudo LD_PRELOAD", category="Linux",
        description="Hijack library imports by maintaining LD_PRELOAD under sudo.",
        difficulty="Hard", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Sudo_Ld_Pr3l0ad_Hij4ck_!ab1}"
    ),
    23: LabScenario(
        id=23, name="Docker Socket Privilege Escalation", category="Linux",
        description="Mount host disk files via Docker daemon socket connection.",
        difficulty="Hard", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Dock3r_Sock3t_Root_M0unt_@ff}"
    ),
    24: LabScenario(
        id=24, name="NFS Root Squashing (no_root_squash)", category="Linux",
        description="Create SUID payloads inside writable NFS network exports.",
        difficulty="Hard", initial_user="student", initial_dir="C:\\home\\student",
        flag="FLAG{Nfs_No_R00t_Squ4sh_Su1d_#fa}"
    )
}
