import os, time, psycopg2, psutil
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, unset_jwt_cookies
from flask_bcrypt import Bcrypt
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-super-secret-key')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
app.start_time = time.time()

def get_db_conn():
    return psycopg2.connect(
        dbname=os.environ.get('POSTGRES_DB', 'labdb'),
        user=os.environ.get('POSTGRES_USER', 'labuser'),
        password=os.environ.get('POSTGRES_PASSWORD', 'labpass'),
        host=os.environ.get('POSTGRES_HOST', 'db'),
        port=os.environ.get('POSTGRES_PORT', 5432),
    )

def ensure_tables():
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(200) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS logins (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS failed_logins (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[FATAL] Errore nella creazione/verifica tabelle: {e}")

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == "OPTIONS":
        return '', 200
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=%s;", (username,))
        row = cur.fetchone()
        if not row or not bcrypt.check_password_hash(row[0], password):
            cur.execute("INSERT INTO failed_logins (username) VALUES (%s);", (username,))
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"msg": "Credenziali errate!"}), 401
        cur.execute("INSERT INTO logins (username) VALUES (%s);", (username,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("Errore database:", e)
        return jsonify({"msg": "Errore database!"}), 500
    access_token = create_access_token(identity=username)
    resp = jsonify(success=True)
    resp.set_cookie('access_token_cookie', access_token, httponly=True, samesite="Lax")
    return resp, 200

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == "OPTIONS":
        return '', 200
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({"msg": "Compila tutti i campi!"}), 400
    if len(password) < 8:
        return jsonify({"msg": "Password troppo corta!"}), 400
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=%s;", (username,))
        if cur.fetchone():
            return jsonify({"msg": "Username già esistente!"}), 409
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s);", (username, pw_hash))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"msg": f"Errore database: {e}"}), 500
    return jsonify(success=True), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    resp = jsonify({"msg": "Logout effettuato."})
    unset_jwt_cookies(resp)
    return resp, 200

@app.route('/api/stats')
@jwt_required()
def stats():
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users;")
        user_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM logins WHERE date_trunc('day', ts) = date_trunc('day', now());")
        logins_today = cur.fetchone()[0]
        cur.execute("SELECT username, ts FROM logins ORDER BY ts DESC LIMIT 10;")
        last_logins = [{"username":u,"ts":str(t)} for u,t in cur.fetchall()]
        cur.execute("""
            SELECT to_char(ts, 'YYYY-MM-DD'), COUNT(*)
            FROM logins WHERE ts > NOW() - INTERVAL '7 days'
            GROUP BY 1 ORDER BY 1
        """)
        login_trend = [{"day": d, "count": c} for d, c in cur.fetchall()]
        cur.execute("""
            SELECT to_char(created_at, 'YYYY-MM-DD'), COUNT(*)
            FROM users WHERE created_at > NOW() - INTERVAL '7 days'
            GROUP BY 1 ORDER BY 1
        """)
        users_trend = [{"day": d, "count": c} for d, c in cur.fetchall()]
        cur.execute("""
            SELECT
                (SELECT COUNT(*) FROM logins WHERE ts > NOW() - INTERVAL '24 hours') as ok,
                (SELECT COUNT(*) FROM failed_logins WHERE ts > NOW() - INTERVAL '24 hours') as failed
        """)
        ok, failed = cur.fetchone()
        login_success_rate = int(100 * ok / (ok + failed)) if (ok + failed) > 0 else 100
        cur.close(); conn.close()
    except Exception as e:
        user_count, logins_today, last_logins, login_trend, users_trend, login_success_rate = None, None, [], [], [], 100
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    uptime = int(time.time() - app.start_time)
    pod_count = os.environ.get("POD_COUNT", "1")
    replica_count = os.environ.get("REPLICA_COUNT", "1")
    return jsonify(
        user_count=user_count,
        logins_today=logins_today,
        last_logins=last_logins,
        login_trend=login_trend,
        users_trend=users_trend,
        login_success_rate=login_success_rate,
        cpu=cpu, ram=ram,
        uptime=uptime,
        pod_count=pod_count,
        replica_count=replica_count
    )

@app.route('/healthz')
def healthz():
    return "OK", 200

if __name__ == '__main__':
    ensure_tables()
    app.run(host='0.0.0.0', port=5000)