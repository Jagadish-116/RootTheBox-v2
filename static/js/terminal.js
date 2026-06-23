class Terminal {
    constructor(terminalInputId, terminalScreenId, terminalHistoryId, terminalPromptId) {
        this.input = document.getElementById(terminalInputId);
        this.screen = document.getElementById(terminalScreenId);
        this.history = document.getElementById(terminalHistoryId);
        this.prompt = document.getElementById(terminalPromptId);
        
        this.commandHistory = [];
        this.historyIndex = -1;
        this.currentShellMode = 'CMD'; // CMD or PS
        this.currentCwd = 'C:\\Users\\labuser';
        this.currentUsername = 'labuser';
        this.activeScenarioId = 1;
        this.category = 'Windows'; // Windows or Linux
        
        this.initListeners();
    }
    
    initListeners() {
        // Focus input on clicking anywhere in the terminal body
        this.screen.addEventListener('click', () => {
            this.input.focus();
        });
        
        // Listen to key events in terminal input
        this.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.handleEnter();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.navigateHistory('up');
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.navigateHistory('down');
            } else if (e.key === 'Tab') {
                e.preventDefault();
                this.handleTabCompletion();
            }
        });
        
        // Listen to tab changes (only applicable for Windows)
        const cmdTab = document.getElementById('shell-cmd');
        const psTab = document.getElementById('shell-ps');
        
        if (cmdTab && psTab) {
            cmdTab.addEventListener('click', () => {
                this.setShellMode('CMD');
                cmdTab.classList.add('active');
                psTab.classList.remove('active');
            });
            psTab.addEventListener('click', () => {
                this.setShellMode('PS');
                psTab.classList.add('active');
                cmdTab.classList.remove('active');
            });
        }
    }
    
    setScenario(scenarioId) {
        this.activeScenarioId = scenarioId;
    }
    
    setShellMode(mode) {
        this.currentShellMode = mode;
        this.updatePrompt();
        
        // Update title bar
        const titleText = document.getElementById('terminal-title-text');
        if (titleText) {
            titleText.innerHTML = `<i class="fa-solid fa-terminal"></i> ${mode === 'PS' ? 'PowerShell' : 'Command Prompt'} - Administrator Mode`;
        }
    }
    
    updatePrompt() {
        if (this.category === 'Linux') {
            const symbol = this.currentUsername === 'root' ? '#' : '$';
            this.prompt.innerHTML = `${this.currentUsername}@rootthebox:${this.currentCwd}${symbol}&nbsp;`;
        } else {
            if (this.currentShellMode === 'PS') {
                this.prompt.innerHTML = `PS ${this.currentCwd}&gt;`;
            } else {
                this.prompt.innerHTML = `${this.currentCwd}&gt;`;
            }
        }
        // Auto scroll to bottom
        this.screen.scrollTop = this.screen.scrollHeight;
    }
    
    writeOutput(text, isError = false) {
        const line = document.createElement('div');
        line.className = 'terminal-line' + (isError ? ' text-glow-red' : '');
        // Preserve spacing and format newlines
        line.textContent = text;
        this.history.appendChild(line);
        this.screen.scrollTop = this.screen.scrollHeight;
    }
    
    clearOutput() {
        this.history.innerHTML = '';
    }
    
    handleEnter() {
        const cmdText = this.input.value;
        this.input.value = '';
        
        if (!cmdText.trim()) return;
        
        // Add to history
        this.commandHistory.push(cmdText);
        this.historyIndex = this.commandHistory.length;
        
        // Display executed command
        const promptText = this.prompt.textContent;
        this.writeOutput(`${promptText} ${cmdText}`);
        
        // Local commands
        const cleanCmd = cmdText.toLowerCase().trim();
        if (cleanCmd === 'cls' || cleanCmd === 'clear') {
            this.clearOutput();
            return;
        }
        
        // Send command to backend API
        this.sendCmdToBackend(cmdText);
    }
    
    async sendCmdToBackend(cmdText) {
        try {
            const response = await fetch('/api/cmd', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    cmd: cmdText,
                    scenario_id: this.activeScenarioId
                })
            });
            
            if (!response.ok) {
                throw new Error("HTTP error " + response.status);
            }
            
            const data = await response.json();
            
            if (data.stderr) {
                this.writeOutput(data.stderr, true);
            }
            if (data.stdout) {
                this.writeOutput(data.stdout);
            }
            
            // Update metadata
            this.currentCwd = data.cwd;
            this.currentUsername = data.username;
            this.category = data.category || 'Windows';
            this.updatePrompt();
            
            // Update active user badge
            const badge = document.getElementById('active-user-badge');
            if (data.escalated) {
                badge.textContent = this.category === 'Linux' ? 'root' : 'SYSTEM';
                badge.className = 'status-value text-glow-cyan';
            } else {
                badge.textContent = data.username;
                badge.className = 'status-value text-glow-green';
            }
            
        } catch (err) {
            this.writeOutput(`[Error communicating with backend: ${err.message}]`, true);
        }
    }
    
    navigateHistory(direction) {
        if (this.commandHistory.length === 0) return;
        
        if (direction === 'up') {
            if (this.historyIndex > 0) {
                this.historyIndex--;
                this.input.value = this.commandHistory[this.historyIndex];
            }
        } else if (direction === 'down') {
            if (this.historyIndex < this.commandHistory.length - 1) {
                this.historyIndex++;
                this.input.value = this.commandHistory[this.historyIndex];
            } else {
                this.historyIndex = this.commandHistory.length;
                this.input.value = '';
            }
        }
    }
    
    handleTabCompletion() {
        const inputVal = this.input.value.trim().toLowerCase();
        if (!inputVal) return;
        
        const winCommands = ['whoami', 'cd', 'dir', 'type', 'icacls', 'sc', 'reg', 'net', 'msiexec', 'printspoofer.exe', 'juicypotato.exe'];
        const lnxCommands = ['whoami', 'id', 'cd', 'ls', 'cat', 'echo', 'mkdir', 'rm', 'sudo', 'su', 'tar', 'python3', 'docker', 'chmod'];
        
        const list = this.category === 'Linux' ? lnxCommands : winCommands;
        const matches = list.filter(c => c.startsWith(inputVal));
        
        if (matches.length === 1) {
            this.input.value = matches[0] + ' ';
        } else if (matches.length > 1) {
            this.writeOutput(`\nPossible commands: ${matches.join(', ')}`);
            this.updatePrompt();
        }
    }
}
