"""
CTF Challenge: "Broken Login"
Target web app vulnerable to SQL Injection (OR 1=1 --)

This is intentionally vulnerable for educational purposes.
DO NOT deploy in production.
"""

import sqlite3
import os

from flask import Flask, request, render_template_string

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

# The real flag is stored ONLY in the database, not in source code.
FLAG = "CTF{sqli_0r_1_eq_1_byp4ss}"


def init_db():
    """Create the users table and seed one admin user."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        """
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        )
        """
    )
    # Only the admin knows the flag — regular users don't
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("admin", "s3cr3t_p4ssw0rd_y0u_w1ll_never_gu3ss", "admin"),
    )
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("alice", "password123", "user"),
    )
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("bob", "qwerty", "user"),
    )
    con.commit()
    con.close()


# ---------------------------------------------------------------------------
# Intentionally vulnerable login query
# ---------------------------------------------------------------------------
def login_user(username: str, password: str):
    """
    WARNING: This query is intentionally vulnerable to SQL injection.
    The username and password are inserted directly into the query string
    without any sanitisation or parameterisation.

    Vulnerable query example:
        SELECT * FROM users WHERE username = 'admin' AND password = 'wrong'
    
    With payload  ' OR 1=1 --  the query becomes:
        SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '...'
    which is always TRUE → returns the first row (admin).
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # ⚠️  DO NOT do this in real code — use parameterised queries instead!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    print(f"[DEBUG] Executing: {query}")   # visible in server logs (intentional)

    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.OperationalError as e:
        con.close()
        return None, str(e)

    con.close()
    return row, None


# ---------------------------------------------------------------------------
# HTML templates (inline for simplicity)
# ---------------------------------------------------------------------------
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Broken Login - CTF Challenge</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      background: #0d1117;
      font-family: 'Courier New', monospace;
      color: #c9d1d9;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 10px;
      padding: 40px 50px;
      width: 400px;
      box-shadow: 0 0 40px rgba(88,166,255,0.08);
    }
    h1 { color: #58a6ff; margin-bottom: 8px; font-size: 1.4rem; }
    .subtitle { color: #8b949e; font-size: 0.85rem; margin-bottom: 28px; }
    label { display: block; margin-bottom: 6px; color: #8b949e; font-size: 0.85rem; }
    input {
      width: 100%; padding: 10px 14px;
      background: #0d1117; border: 1px solid #30363d;
      border-radius: 6px; color: #c9d1d9;
      font-family: 'Courier New', monospace;
      font-size: 0.9rem; margin-bottom: 18px;
      transition: border-color 0.2s;
    }
    input:focus { outline: none; border-color: #58a6ff; }
    button {
      width: 100%; padding: 11px;
      background: #238636; border: none; border-radius: 6px;
      color: #fff; font-size: 0.95rem; cursor: pointer;
      transition: background 0.2s;
    }
    button:hover { background: #2ea043; }
    .error {
      background: rgba(248,81,73,0.1);
      border: 1px solid #f85149;
      border-radius: 6px; padding: 10px 14px;
      color: #f85149; margin-bottom: 16px; font-size: 0.85rem;
    }
    .hint {
      margin-top: 20px; padding: 12px;
      background: rgba(88,166,255,0.06);
      border-left: 3px solid #58a6ff;
      border-radius: 4px; font-size: 0.8rem; color: #8b949e;
    }
    .hint code { color: #79c0ff; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 Admin Login</h1>
    <p class="subtitle">Sistema de administración interno — sólo personal autorizado</p>

    {% if error %}
    <div class="error">⚠️ {{ error }}</div>
    {% endif %}

    <form method="POST" action="/login">
      <label for="username">Usuario</label>
      <input id="username" name="username" type="text" placeholder="usuario" autocomplete="off" required>

      <label for="password">Contraseña</label>
      <input id="password" name="password" type="password" placeholder="••••••••" required>

      <button type="submit">Iniciar sesión</button>
    </form>

    <div class="hint">
      💡 <strong>Pista del reto:</strong> ¿Has probado qué pasa si el servidor
      no valida correctamente tu entrada? Prueba con
      <code>' OR 1=1 --</code> en el campo de usuario.
    </div>
  </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Dashboard - CTF Challenge</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      background: #0d1117;
      font-family: 'Courier New', monospace;
      color: #c9d1d9;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 10px;
      padding: 40px 50px;
      max-width: 550px; width: 100%;
      box-shadow: 0 0 40px rgba(63,185,80,0.1);
    }
    h1 { color: #3fb950; margin-bottom: 8px; font-size: 1.4rem; }
    .subtitle { color: #8b949e; font-size: 0.85rem; margin-bottom: 28px; }
    .user-info {
      background: #0d1117; border: 1px solid #30363d;
      border-radius: 6px; padding: 16px; margin-bottom: 20px;
    }
    .user-info p { margin-bottom: 6px; font-size: 0.9rem; }
    .user-info span { color: #79c0ff; }
    .flag-box {
      background: rgba(63,185,80,0.08);
      border: 2px solid #3fb950;
      border-radius: 8px; padding: 20px;
      text-align: center;
    }
    .flag-label { color: #8b949e; font-size: 0.8rem; margin-bottom: 10px; }
    .flag-value {
      color: #3fb950; font-size: 1.1rem;
      font-weight: bold; letter-spacing: 1px;
    }
    .query-box {
      margin-top: 20px;
      background: #0d1117; border: 1px solid #30363d;
      border-radius: 6px; padding: 14px;
      font-size: 0.8rem;
    }
    .query-box .label { color: #8b949e; margin-bottom: 6px; }
    .query-box code { color: #f85149; word-break: break-all; }
    a {
      display: inline-block; margin-top: 18px;
      color: #58a6ff; text-decoration: none; font-size: 0.85rem;
    }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <h1>✅ Acceso concedido</h1>
    <p class="subtitle">Has bypasseado el login con SQL Injection.</p>

    <div class="user-info">
      <p>ID: <span>{{ user_id }}</span></p>
      <p>Usuario: <span>{{ username }}</span></p>
      <p>Rol: <span>{{ role }}</span></p>
    </div>

    <div class="flag-box">
      <div class="flag-label">🚩 FLAG</div>
      <div class="flag-value">{{ flag }}</div>
    </div>

    <div class="query-box">
      <div class="label">Query ejecutada en el servidor:</div>
      <code>{{ query }}</code>
    </div>

    <a href="/">← Volver al login</a>
  </div>
</body>
</html>
"""

ERROR_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Error SQL - CTF Challenge</title>
  <style>
    * { box-sizing: border-box; }
    body {
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: #0d1117; font-family: 'Courier New', monospace; color: #c9d1d9;
    }
    .card {
      background: #161b22; border: 1px solid #f85149;
      border-radius: 10px; padding: 40px 50px; max-width: 550px; width: 100%;
    }
    h1 { color: #f85149; margin-bottom: 14px; }
    pre {
      background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
      padding: 14px; color: #f85149; font-size: 0.85rem;
      white-space: pre-wrap; word-break: break-all;
    }
    a { display: inline-block; margin-top: 16px; color: #58a6ff; text-decoration: none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>⚠️ Error SQL</h1>
    <p style="color:#8b949e; margin-bottom:14px;">Tu payload causó un error en la base de datos:</p>
    <pre>{{ error }}</pre>
    <a href="/">← Volver al login</a>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_TEMPLATE)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    row, sql_error = login_user(username, password)

    if sql_error:
        # Intentionally leak the SQL error — gives attackers useful info
        return render_template_string(ERROR_TEMPLATE, error=sql_error), 400

    if row:
        user_id, db_username, db_password, db_role = row
        # Build the query string for display purposes
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{password}'"
        )
        return render_template_string(
            DASHBOARD_TEMPLATE,
            user_id=user_id,
            username=db_username,
            role=db_role,
            flag=FLAG,
            query=query,
        )
    else:
        return render_template_string(
            LOGIN_TEMPLATE,
            error="Credenciales incorrectas. Acceso denegado.",
        ), 401


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("[*] Inicializando base de datos...")
    init_db()
    print("[*] Servidor iniciado en http://localhost:5001")
    print("[*] ADVERTENCIA: Esta app es intencionalmente vulnerable — sólo para CTF")
    app.run(host="0.0.0.0", port=5001, debug=False)
