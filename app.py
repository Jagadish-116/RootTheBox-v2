import uuid
from flask import Flask, render_template, request, jsonify, session
from engine import TerminalSession
from scenarios import SCENARIOS

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'cyber_security_lab_secret_key_1337'

# In-memory store for active sessions (Stays alive perfectly on Render!)
sessions = {}

def get_or_create_session(scenario_id=1):
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
        
    sess_id = session['session_id']
    
    if sess_id not in sessions or sessions[sess_id].scenario_id != scenario_id:
        sessions[sess_id] = TerminalSession(scenario_id)
        
    return sessions[sess_id]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scenarios', methods=['GET'])
def get_scenarios():
    data = []
    for s in SCENARIOS.values():
        data.append({
            "id": s.id,
            "name": s.name,
            "category": s.category,
            "description": s.description,
            "difficulty": s.difficulty,
            "initial_user": s.initial_user,
            "initial_dir": s.initial_dir
        })
    return jsonify(data)

@app.route('/api/init', methods=['POST'])
def init_scenario():
    data = request.json or {}
    scenario_id = int(data.get('scenario_id', 1))
    
    if scenario_id not in SCENARIOS:
        return jsonify({"error": "Invalid scenario ID"}), 400
        
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
        
    sess_id = session['session_id']
    sessions[sess_id] = TerminalSession(scenario_id)
    term_sess = sessions[sess_id]
    
    prompt_user = term_sess.current_user
    cwd = term_sess.current_dir
    
    if term_sess.os == "Linux":
        welcome_msg = f"Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)\n\n"
        welcome_msg += f"Logged in as: {prompt_user}\nType 'help' for command listing.\n"
    else:
        welcome_msg = f"Microsoft Windows [Version 10.0.19041.1]\n(c) 2026 Microsoft Corporation. All rights reserved.\n\n"
        if scenario_id == 4:
            welcome_msg += "Connecting to local service terminal shell...\nConnection established.\nType 'help' for command listing.\n"
        else:
            welcome_msg += f"Logged in as: {prompt_user}\nType 'help' for command listing.\n"
        
    return jsonify({
        "status": "initialized",
        "welcome": welcome_msg,
        "username": prompt_user,
        "cwd": cwd,
        "escalated": term_sess.escalated,
        "category": term_sess.os
    })

@app.route('/api/cmd', methods=['POST'])
def run_command():
    data = request.json or {}
    cmd = data.get('cmd', '')
    scenario_id = int(data.get('scenario_id', 1))
    
    term_sess = get_or_create_session(scenario_id)
    stdout, stderr, cwd = term_sess.execute_command(cmd)
    
    return jsonify({
        "stdout": stdout,
        "stderr": stderr,
        "cwd": cwd,
        "username": term_sess.current_user,
        "escalated": term_sess.escalated,
        "category": term_sess.os
    })

@app.route('/api/submit-flag', methods=['POST'])
def submit_flag():
    data = request.json or {}
    scenario_id = int(data.get('scenario_id', 1))
    submitted_flag = data.get('flag', '').strip()
    
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        return jsonify({"success": False, "message": "Invalid scenario"}), 400
        
    term_sess = get_or_create_session(scenario_id)
        
    if submitted_flag == scenario.flag:
        return jsonify({
            "success": True,
            "message": "Flag is CORRECT! Outstanding job! You have successfully mastered this privilege escalation vector."
        })
    else:
        return jsonify({
            "success": False,
            "message": "Incorrect flag. Enumerate further, examine the permissions, and make sure you run the exploit successfully."
        })

if __name__ == '__main__':
    app.run(debug=True)
