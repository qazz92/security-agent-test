"""
Flask 애플리케이션 with 의도적인 보안 취약점들
이 파일은 교육/데모 목적으로만 사용되며, 실제 환경에서는 절대 사용하지 마세요.
"""

from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import pickle
import os
import yaml
import subprocess

app = Flask(__name__)

# 취약점 1: 하드코딩된 시크릿
SECRET_KEY = "my-super-secret-key-123"  # 위험! 환경변수를 사용해야 함
app.secret_key = SECRET_KEY

# 취약점 2: 하드코딩된 데이터베이스 비밀번호
DB_PASSWORD = "admin123"  # 위험!
API_KEY = "sk-1234567890abcdef"  # 위험!

# 데이터베이스 초기화
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'userpass', 'user@example.com')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return '''
    <h1>Hello World - Vulnerable Demo App</h1>
    <p><a href="/user/1">View User Profile</a></p>
    <p><a href="/search">Search Users</a></p>
    <p><a href="/comment">Add Comment</a></p>
    <p><a href="/upload">Upload File</a></p>
    <p><a href="/admin">Admin Panel</a></p>
    '''

# 취약점 3: SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # 위험! f-string을 사용한 SQL 쿼리 - SQL Injection 취약점
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return f"<h2>User Profile</h2><p>ID: {user[0]}<br>Username: {user[1]}<br>Email: {user[3]}</p>"
    else:
        return "User not found"

# 취약점 4: SQL Injection (검색 기능)
@app.route('/search')
def search_users():
    search_term = request.args.get('q', '')
    if search_term:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # 위험! 사용자 입력을 직접 쿼리에 삽입
        query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%'"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()

        result_html = "<h2>Search Results</h2>"
        for result in results:
            result_html += f"<p>Username: {result[0]}, Email: {result[1]}</p>"
        return result_html
    else:
        return '''
        <h2>User Search</h2>
        <form>
            <input type="text" name="q" placeholder="Search username">
            <button type="submit">Search</button>
        </form>
        '''

# 취약점 5: XSS (Cross-Site Scripting)
@app.route('/comment', methods=['GET', 'POST'])
def add_comment():
    if request.method == 'POST':
        comment = request.form['comment']
        # 위험! 사용자 입력을 직접 HTML로 렌더링 - XSS 취약점
        return f"<h2>Your Comment</h2><div>{comment}</div><a href='/comment'>Add another comment</a>"
    else:
        return '''
        <h2>Add Comment</h2>
        <form method="post">
            <textarea name="comment" placeholder="Enter your comment"></textarea><br>
            <button type="submit">Submit</button>
        </form>
        '''

# 취약점 6: 안전하지 않은 Deserialization
@app.route('/save_data', methods=['POST'])
def save_data():
    data = request.get_data()
    # 위험! pickle.loads()는 임의 코드 실행 가능
    try:
        obj = pickle.loads(data)
        return f"Data saved: {obj}"
    except Exception as e:
        return f"Error: {e}"

# 취약점 7: Directory Traversal
@app.route('/read_file')
def read_file():
    filename = request.args.get('file', 'readme.txt')
    try:
        # 위험! 사용자 입력으로 파일 경로 생성 - Directory Traversal
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error reading file: {e}"

# 취약점 8: Command Injection
@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    try:
        # 위험! 사용자 입력을 shell 명령어에 직접 사용
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
        return f"<pre>{result}</pre>"
    except Exception as e:
        return f"Error: {e}"

# 취약점 9: YAML Deserialization
@app.route('/load_config', methods=['POST'])
def load_config():
    config_data = request.form['config']
    try:
        # 위험! yaml.load()는 임의 코드 실행 가능
        config = yaml.load(config_data, Loader=yaml.Loader)
        return f"Config loaded: {config}"
    except Exception as e:
        return f"Error: {e}"

# 취약점 10: 약한 세션 관리
@app.route('/admin')
def admin_panel():
    # 위험! 간단한 쿠키 기반 인증
    if request.cookies.get('admin') == 'true':
        return '''
        <h2>Admin Panel</h2>
        <p>Welcome, Admin! Here are sensitive operations:</p>
        <ul>
            <li><a href="/delete_user?id=1">Delete User 1</a></li>
            <li><a href="/backup_db">Download Database</a></li>
        </ul>
        '''
    else:
        return '''
        <h2>Admin Login</h2>
        <p>Access the admin panel by setting the admin cookie to 'true'</p>
        <script>document.cookie = "admin=false";</script>
        '''

# 취약점 11: 정보 노출
@app.route('/debug')
def debug_info():
    # 위험! 민감한 환경 변수 노출
    env_vars = dict(os.environ)
    return f"<pre>Environment Variables:\n{env_vars}</pre>"

# 취약점 12: 업로드 취약점
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # 위험! 파일 타입 검증 없이 업로드
            filename = file.filename
            file.save(f"uploads/{filename}")
            return f"File {filename} uploaded successfully!"

    return '''
    <h2>File Upload</h2>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
    '''

# 취약점 13: SSRF (Server-Side Request Forgery)
@app.route('/fetch_url')
def fetch_url():
    import requests
    url = request.args.get('url', '')
    if url:
        try:
            # 위험! 사용자가 제공한 URL로 요청 - SSRF 취약점
            # 공격자가 내부 네트워크 스캔 가능 (예: http://localhost:22, http://169.254.169.254/latest/meta-data/)
            response = requests.get(url, timeout=5)
            return f"<h2>Fetched Content</h2><pre>{response.text[:1000]}</pre>"
        except Exception as e:
            return f"Error: {e}"
    else:
        return '''
        <h2>Fetch URL</h2>
        <form>
            <input type="text" name="url" placeholder="Enter URL">
            <button type="submit">Fetch</button>
        </form>
        '''

# 취약점 14: XXE (XML External Entity)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    xml_data = request.form['xml']
    try:
        # 위험! 외부 엔티티 처리가 활성화된 XML 파싱
        # 공격자가 로컬 파일 읽기 가능 (예: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>)
        root = ET.fromstring(xml_data)
        return f"<h2>Parsed XML</h2><p>Root tag: {root.tag}</p>"
    except Exception as e:
        return f"Error: {e}"

# 취약점 15: Open Redirect
@app.route('/redirect')
def redirect_user():
    # 위험! 사용자 입력으로 리디렉션 URL 결정
    # 피싱 공격에 악용 가능 (예: /redirect?url=http://evil.com)
    redirect_url = request.args.get('url', '/')
    return redirect(redirect_url)

# 취약점 16: IDOR (Insecure Direct Object Reference)
@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    # 위험! 권한 검증 없이 모든 사용자 프로필 접근 가능
    # 공격자가 user_id를 변경하여 다른 사용자 정보 조회
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return f'''
        <h2>User Profile #{user_id}</h2>
        <p>Username: {user[1]}</p>
        <p>Email: {user[3]}</p>
        <p>Password Hash: {user[2]}</p>
        '''
    return "User not found"

# 취약점 17: Race Condition (TOCTOU)
@app.route('/withdraw', methods=['POST'])
def withdraw_money():
    # 위험! Race condition 취약점
    # 동시 요청으로 잔액 이상 출금 가능
    user_id = request.form.get('user_id')
    amount = int(request.form.get('amount', 0))

    # Check balance (Time-of-Check)
    balance = get_balance(user_id)
    if balance >= amount:
        # Use balance (Time-of-Use) - 여기서 race condition 발생
        import time
        time.sleep(0.1)  # 의도적 지연
        new_balance = balance - amount
        update_balance(user_id, new_balance)
        return f"Withdrawn ${amount}. New balance: ${new_balance}"
    else:
        return "Insufficient funds"

def get_balance(user_id):
    return 1000  # 시뮬레이션용

def update_balance(user_id, balance):
    pass  # 시뮬레이션용

# 취약점 18: Weak Cryptography
@app.route('/encrypt')
def encrypt_data():
    import hashlib
    data = request.args.get('data', '')
    # 위험! MD5는 더 이상 안전하지 않음
    hash_value = hashlib.md5(data.encode()).hexdigest()
    return f"<p>MD5 Hash: {hash_value}</p>"

# 취약점 19: Insufficient Logging
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # 위험! 실패한 로그인 시도가 로깅되지 않음
    # 무차별 대입 공격 탐지 불가
    if username == 'admin' and password == 'password123':
        session['user'] = username
        return "Login successful"
    else:
        return "Login failed"  # 로깅 없음

# 취약점 20: Mass Assignment
@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form.get('user_id')
    # 위험! 모든 form 필드를 직접 DB에 업데이트
    # 공격자가 is_admin=true 같은 필드를 추가 가능
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 의도: username, email만 업데이트
    # 실제: form에서 받은 모든 필드 업데이트 가능
    update_fields = []
    for key, value in request.form.items():
        if key != 'user_id':
            update_fields.append(f"{key} = '{value}'")

    if update_fields:
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = {user_id}"
        cursor.execute(query)
        conn.commit()
    conn.close()

    return "User updated successfully"

if __name__ == '__main__':
    init_db()
    os.makedirs('uploads', exist_ok=True)
    # 위험! Debug 모드가 활성화됨
    app.run(debug=True, host='0.0.0.0', port=5000)