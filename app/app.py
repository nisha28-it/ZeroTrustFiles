from flask import Flask, request, jsonify, send_file, session, render_template_string
import os
import requests
import sqlite3
import uuid
from datetime import datetime
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "local-demo-only-change-me")

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181").rstrip("/")
STORAGE_DIR = os.environ.get("STORAGE_DIR", "/data/storage")
AUDIT_LOG = os.environ.get("AUDIT_LOG", "/data/logs/access.log")
DB_FILE = os.path.join(STORAGE_DIR, "zerotrust.db")

# Ensure directories exist
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT)''')
    # Files table
    c.execute('''CREATE TABLE IF NOT EXISTS files 
                 (id INTEGER PRIMARY KEY, filename TEXT, owner TEXT, classification TEXT, filepath TEXT, key BLOB)''')
    conn.commit()
    
    # Create test users if none exist
    c.execute("SELECT * FROM users WHERE username='analyst01'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                  ("analyst01", generate_password_hash("password123"), "analyst"))
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                  ("admin01", generate_password_hash("admin123"), "admin"))
        conn.commit()
    conn.close()

init_db()

# --- AUDIT LOGGING ---
def log_event(user, action, filename, decision, reason=""):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    log_entry = f"[{timestamp}] User: {user} | Action: {action} | File: {filename} | Decision: {decision} | Reason: {reason}\n"
    with open(AUDIT_LOG, "a") as f:
        f.write(log_entry)

# --- ZERO TRUST POLICY CHECK ---
def ask_policy(policy_input):
    try:
        response = requests.post(
            f'{OPA_URL}/v1/data/zerotrust/files/allow',
            json={"input": policy_input},
            timeout=3,
        )
        return response.json().get("result", False) is True
    except Exception as e:
        print(f"OPA Error: {e}")
        return False

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[0], password):
            session['username'] = username
            session['role'] = user[1]
            log_event(username, "LOGIN", "N/A", "ALLOW")
            return jsonify({"message": "Login successful", "role": user[1]}), 200
        
        log_event(username, "LOGIN", "N/A", "DENY", "Invalid credentials")
        return jsonify({"error": "Invalid credentials"}), 401
    
    return '''
        <h2>Zero Trust Login</h2>
        <form id="loginForm">
            Username: <input type="text" id="username" value="analyst01"><br><br>
            Password: <input type="password" id="password" value="password123"><br><br>
            <button type="button" onclick="doLogin()">Login</button>
        </form>
        <script>
            function doLogin() {
                fetch('/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value
                    })
                }).then(res => res.json()).then(data => alert(JSON.stringify(data)));
            }
        </script>
    '''

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return "Please login first at /login", 401

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        filename = file.filename
        classification = request.form.get('classification', 'internal')
        user = session['username']
        role = session['role']
        device_status = "compliant" # Simulated for demo

        # 1. Ask OPA
        policy_input = {"user": user, "role": role, "action": "upload", "filename": filename, "device": device_status}
        if not ask_policy(policy_input):
            log_event(user, "UPLOAD", filename, "DENY", "OPA Policy Violation")
            return jsonify({"error": "Access Denied by Zero Trust Policy"}), 403

        # 2. Encrypt File
        file_data = file.read()
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(file_data)

        # 3. Save encrypted file
        file_id = str(uuid.uuid4())
        filepath = os.path.join(STORAGE_DIR, file_id)
        with open(filepath, "wb") as f:
            f.write(encrypted_data)

        # 4. Save metadata
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO files (filename, owner, classification, filepath, key) VALUES (?, ?, ?, ?, ?)",
                  (filename, user, classification, filepath, key))
        conn.commit()
        conn.close()

        log_event(user, "UPLOAD", filename, "ALLOW")
        return jsonify({"message": f"File '{filename}' uploaded and encrypted successfully!"}), 200

    # Simple HTML for upload
    return '''
        <h2>Upload File (Zero Trust)</h2>
        <p>Logged in as: ''' + session['username'] + ''' (''' + session['role'] + ''')</p>
        <form id="uploadForm">
            <input type="file" id="fileInput" required><br><br>
            <select id="classification">
                <option value="internal">Internal</option>
                <option value="confidential">Confidential</option>
            </select><br><br>
            <button type="button" onclick="doUpload()">Upload</button>
        </form>
        <script>
            function doUpload() {
                let formData = new FormData();
                formData.append("file", document.getElementById('fileInput').files[0]);
                formData.append("classification", document.getElementById('classification').value);
                
                fetch('/upload', { method: 'POST', body: formData })
                .then(res => res.json()).then(data => alert(JSON.stringify(data)));
            }
        </script>
    '''

@app.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    if 'username' not in session:
        return "Please login first at /login", 401

    user = session['username']
    role = session['role']
    device_status = "compliant"

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT filename, owner, classification, filepath, key FROM files WHERE id=?", (file_id,))
    file_record = c.fetchone()
    conn.close()

    if not file_record:
        return jsonify({"error": "File not found"}), 404

    filename, owner, classification, filepath, key = file_record

    # 1. Ask OPA
    policy_input = {"user": user, "role": role, "action": "download", "owner": owner, "classification": classification, "device": device_status}
    if not ask_policy(policy_input):
        log_event(user, "DOWNLOAD", filename, "DENY", "OPA Policy Violation")
        return jsonify({"error": "Access Denied by Zero Trust Policy"}), 403

    # 2. Decrypt File
    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    cipher = Fernet(key)
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception as e:
        return jsonify({"error": "Decryption failed. File may be corrupted."}), 500

    log_event(user, "DOWNLOAD", filename, "ALLOW")
    
    import io
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )
@app.route('/')
def home():
    return "<h1>Zero Trust File Sharing System</h1><p>System is active. Please go to <a href='/login'>/login</a> to sign in.</p>"
@app.route('/health')
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)