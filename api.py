import os
import sys
import uuid
import pickle
import base64
from flask import Flask, render_template, request, jsonify, session
import serverless_wsgi

# 🛠️ Fix import pathways for Netlify environment execution runtime
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from engine import TerminalSession
from scenarios import SCENARIOS

app = Flask(__name__)
# Secure secret key for signing client-side state tracking cookies
app.secret_key = 'cyber_security_lab_secret_key_1337'

def get_or_create_session(scenario_id=1):
    """
    Retrieves or creates an ephemeral state machine by abstracting 
    the active session object to and from client-side signed browser cookies.
    """
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    
    # Check if a serialized state object already exists in the client cookie
    session_key = f"state_scenario_{scenario_id}"
    
    if session_key in session:
        try:
            # ✅ FIXED: Removed quotes so it evaluates the variable key correctly
            serialized_data = base64.b64decode(session[session_key].encode('utf-8'))
            term_sess = pickle.loads(serialized_data)
            if term_sess.scenario_id == scenario_id:
                return term_sess
        except Exception:
            # Fallback if serialization format mismatches or updates
            pass

    # If no valid cookie state found, instantiate a fresh virtual lab state machine
    term_sess = TerminalSession(scenario_id)
    save_session_state(term_sess, scenario_id)
    return term_sess

def save_session_state(term_sess, scenario_id):
    """
    Serializes the ongoing user shell progress and writes it down to the response cookie.
    """
    session_key = f"state_scenario_{scenario_id}"
    serialized_data = base64.b64encode(pickle.dumps(term_sess)).decode('utf-8')
    session[session_key] = serialized_data

@app.route('/')
def index():
    # Render fallback or index shell
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
        
    # Instantiate clean scenario runtime and immediately save state down to cookie
    term_sess = TerminalSession(scenario_id)
    save_session_state(term_sess, scenario_id)
    
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
    
    # Pull existing virtual system state directly out of incoming client cookie
    term_sess = get_or_create_session(scenario_id)
    
    # Process user action
    stdout, stderr, cwd = term_sess.execute_command(cmd)
    
    # Persist updated virtual machine file configuration state back to user cookie
    save_session_state(term_sess, scenario_id)
    
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

# 🚀 Production Serverless Cloud Entrypoint for Netlify Runtime Engine
def handler(event, context):
    return serverless_wsgi.handle_request(app, event, context)

# Local diagnostic runtime hook (Only triggers if run outside of Netlify container infrastructure)
if __name__ == '__main__':
    print("Starting Windows/Linux Privilege Escalation Lab server locally...")
    print("Point your browser to http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
