# RootTheBox-v2: Interactive Web-Based Terminal & PrivEsc Simulator Hosted on Web
 [https://rootthebox-5vig.onrender.com](https://rootthebox-5vig.onrender.com)

[![Python Version](https://img.shields.io/badge/python-3.12%2B-gold)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask-teal)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

RootTheBox is a lightweight, web-based interactive terminal simulator designed to teach **Linux and Windows Privilege Escalation** safely and efficiently. 

Unlike traditional labs that require heavy Virtual Machines (VMs) or resource-intensive Docker clusters for every user, RootTheBox utilizes an **in-memory Virtual File System (VFS)** built completely in Python. Users can execute classic commands (`ls`, `cd`, `cat`, `sudo -l`) and exploit realistic system misconfigurations directly from their web browser—with zero risk to their host machine and zero complex virtualization overhead.

---

## 🔥 Key Features

* 🛡️ **100% Isolated & Safe:** Commands are parsed and simulated in an abstraction layer. No actual code runs on the host OS.
* ⚡ **Ultra-Lightweight:** Runs seamlessly on low-spec hardware (even a Raspberry Pi) and can scale to dozens of concurrent students easily.
* 📖 **Interactive Guidance:** Side-by-side split screen featuring a real-time documentation/hint panel to guide users through methodologies.
* 🧩 **Modular Scenarios:** Easily add, remove, or customize privilege escalation challenges (SUID binaries, misconfigured cron jobs, weak service permissions) via a clean configuration engine.
* 🎨 **Sleek Dark Theme:** A modern, terminal-inspired user interface built for long hacking sessions.
  
---

## 🛠️ Project Architecture

The project is decoupled into clean, maintainable modules:

```text
├── app.py                  # Core backend server (Flask/FastAPI) managing API routes
├── requirements.txt        # Python dependency manifest
├── engine.py               # Command parsing and string evaluation logic
├── filesystem.py           # In-memory mock OS directory tree and permission maps
├──scenarios.py             # Privilege escalation challenge definitions & vuln states
├── static/                 # Frontend styling and client-side logic
│   ├── css/style.css       # Terminal UI interface design
│   ├── js/terminal.js      # Raw keyboard input and cursor layout tracker
│   └── js/app.js           # API communications and state management controller
└── templates/
    └── index.html          # Core single-page interface shell
```

🚀 Quick Start (Local Setup)
Follow these steps to deploy the local training lab on your machine:

### 1. Clone the Repository
   
```text
git clone [https://github.com/Jagadish-116/RootTheBox-v2.git](https://github.com/Jagadish-116/RootTheBox-v2.git)

```
```text 
cd RootTheBox-v2                                                                   
```

### 2. Set Up a Virtual Environment (Recommended)

#### Windows
```text
python -m venv venv
.\venv\Scripts\activate
```

#### Linux/macOS
``` text
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```text
pip install -r requirements.txt
```

### 4. Launch the Lab

```text
python app.py
```

Open your browser and navigate to http://127.0.0.1:5000 (or the port specified in your console) to start hacking!

## 🎯 Supported Exploitation Tracks (Current & Incoming)

### Linux Privilege Escalation

[x] Abusing SUID/SGID Flags: Finding and exploiting misconfigured system binaries (e.g., cp, nano).

[x] Weak Sudo Permissions: Leveraging dangerous entry rights inside the sudoers file.

[ ] Wildcard Cron Jobs: Explaining cron job hijacking via broad wildcard executions.

### Windows Privilege Escalation

[ ] Unquoted Service Paths: Exploiting spaces in execution paths with weak write permissions.

[ ] AlwaysInstallElevated: Forcing system-level installer privileges through registry manipulation.


## 🤝 Contributing

Want to add a new scenario? You don't need to touch the frontend!

1. Open scenarios.py.

2. Define your target configuration, files, and hint text.

3. Update the virtual directory layout in simulation/filesystem.py.

4. Submit a Pull Request!

## 📜 License
Distributed under the MIT License.

MIT License

Copyright (c) 2026 Jagadish Ponnala (A6)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
