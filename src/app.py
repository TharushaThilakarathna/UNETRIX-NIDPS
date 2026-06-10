"""
================================================================================
UNetrix — Main Backend Entry Point
================================================================================
Auth endpoints:
  POST /api/auth/login           — Login (returns token)
  POST /api/auth/change-password — Change password (requires token)
  POST /api/auth/logout          — Invalidate token
  GET  /api/auth/me              — Current user info

Module blueprints:
  /api/wids/*   → WIFI_IDS/wids_routes.py
  /api/nids/*   → NIDS/nids_routes.py
  /api/usb/*    → USB/usb_routes.py          (uncomment when ready)
  /api/threat/* → THREAT/threat_routes.py

Run:
  sudo python3 app.py
================================================================================
"""

import os
import sys
import signal
import secrets
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS

# ─── SHARED HELPERS ──────────────────────────────────────────────────────────
# shared.py has no imports from app.py or any blueprint — no circular deps.
from shared import (
    get_db, hash_password, create_token, require_auth,
    log, BASE_DIR, DB_PATH, SESSION_HOURS
)

# ─── FLASK APP ────────────────────────────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 5000

app = Flask(__name__)
CORS(
    app,
    origins="*",
    allow_headers=["Content-Type", "X-Auth-Token"],
    methods=["GET", "POST", "OPTIONS"],
    supports_credentials=False
)

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Auth-Token"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# ─── DATABASE INIT ────────────────────────────────────────────────────────────
def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            username       TEXT UNIQUE NOT NULL,
            password_hash  TEXT NOT NULL,
            salt           TEXT NOT NULL,
            must_change_pw INTEGER DEFAULT 0,
            created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login     DATETIME
        );

        CREATE TABLE IF NOT EXISTS auth_tokens (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            username   TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id            TEXT PRIMARY KEY,
            module        TEXT DEFAULT 'wids',
            started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            ended_at      DATETIME,
            total_frames  INTEGER DEFAULT 0,
            total_attacks INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS attacks (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT,
            timestamp    TEXT,
            attack_type  TEXT,
            attacker_mac TEXT,
            victim_mac   TEXT,
            bssid        TEXT,
            ssid         TEXT,
            signal_dbm   INTEGER,
            confidence   REAL,
            is_low_conf  INTEGER DEFAULT 0,
            target_type  TEXT DEFAULT 'Unknown',
            mac_type     TEXT DEFAULT 'Unknown',
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS attacker_profiles (
            mac            TEXT PRIMARY KEY,
            session_id     TEXT,
            first_seen     DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_attacks  INTEGER  DEFAULT 0,
            attack_types   TEXT     DEFAULT '{}',
            mac_type       TEXT     DEFAULT 'Unknown',
            unique_targets INTEGER  DEFAULT 0,
            targets        TEXT     DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS networks (
            bssid      TEXT PRIMARY KEY,
            ssid       TEXT,
            channel    INTEGER,
            frequency  INTEGER,
            signal_dbm INTEGER,
            is_flagged INTEGER DEFAULT 0,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS clients (
            mac              TEXT PRIMARY KEY,
            associated_bssid TEXT,
            signal_dbm       INTEGER,
            frame_count      INTEGER DEFAULT 0,
            first_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen        DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

    existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        salt = secrets.token_hex(16)
        pw_hash = hash_password("abc123", salt)
        conn.execute("""
            INSERT INTO users (username, password_hash, salt, must_change_pw)
            VALUES (?, ?, ?, 1)
        """, ("admin", pw_hash, salt))
        conn.commit()
        log.info("Default admin created (admin / abc123) — must change on first login")
    else:
        log.info("Admin user already exists")

    conn.close()
    log.info("Database initialised at %s", DB_PATH)
    _migrate_db()


def _migrate_db():
    """Apply schema changes needed for existing databases that predate the refactor."""
    conn = get_db()
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()]
        if "module" not in cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN module TEXT DEFAULT 'wids'")
            conn.commit()
            log.info("DB migration: added 'module' column to sessions")
    except Exception as e:
        log.warning("DB migration error: %s", e)
    finally:
        conn.close()


# ─── AUTH ENDPOINTS ───────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = (data.get("password") or "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401

    if hash_password(password, user["salt"]) != user["password_hash"]:
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401

    conn.execute(
        "UPDATE users SET last_login=? WHERE id=?",
        (datetime.now().isoformat(), user["id"])
    )
    conn.commit()
    conn.close()

    token = create_token(user["id"], user["username"])
    log.info("Login success: %s", username)

    return jsonify({
        "token": token,
        "username": user["username"],
        "must_change_pw": bool(user["must_change_pw"]),
        "expires_in": SESSION_HOURS * 3600,
    })


@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def api_change_password():
    data = request.get_json(force=True) or {}
    current_pw = data.get("current_password", "")
    new_pw = data.get("new_password", "")

    if not new_pw or len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    user_id = request.current_user["user_id"]
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if hash_password(current_pw, user["salt"]) != user["password_hash"]:
        conn.close()
        return jsonify({"error": "Current password is incorrect"}), 401

    if current_pw == new_pw:
        conn.close()
        return jsonify({"error": "New password must differ from current"}), 400

    new_salt = secrets.token_hex(16)
    new_hash = hash_password(new_pw, new_salt)

    conn.execute(
        "UPDATE users SET password_hash=?, salt=?, must_change_pw=0 WHERE id=?",
        (new_hash, new_salt, user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": "Password changed successfully"})


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def api_logout():
    token = request.headers.get("X-Auth-Token") or request.args.get("token")
    conn = get_db()
    conn.execute("DELETE FROM auth_tokens WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/auth/me")
@require_auth
def api_me():
    return jsonify({
        "username": request.current_user["username"],
        "must_change_pw": bool(request.current_user["must_change_pw"]),
    })


# ─── HEALTH + SERVE ───────────────────────────────────────────────────────────
@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "ts": datetime.now().isoformat()})


@app.route("/")
def serve_index():
    html_path = BASE_DIR / "index.html"
    if html_path.exists():
        return html_path.read_text()
    return "<h1>index.html not found</h1>", 404


# ─── REGISTER MODULE BLUEPRINTS ──────────────────────────────────────────────
# Imported AFTER app is defined. Each blueprint imports only from shared.py,
# never from app.py — this is what prevents the circular import error.

from WIFI_IDS.wids_routes import wids_bp
app.register_blueprint(wids_bp)
log.info("Blueprint registered: WIDS → /api/wids/*")

from NIDS.nids_routes import nids_bp
app.register_blueprint(nids_bp)
log.info("Blueprint registered: NIDS → /api/nids/*")

from USB.usb_routes import usb_bp
app.register_blueprint(usb_bp)
log.info("Blueprint registered: USB → /api/usb/*")


from THREAT.threat_routes import threat_bp
app.register_blueprint(threat_bp)
log.info("Blueprint registered: THREAT → /api/threat/*")


# ─── GRACEFUL SHUTDOWN ────────────────────────────────────────────────────────
def on_signal(sig, frame):
    log.info("Shutdown signal received")

    # Stop WIDS if running
    try:
        from WIFI_IDS.wids_routes import state as wids_state, stop_wids_processes
        if wids_state.is_running:
            wids_state.is_running = False
            stop_wids_processes()
            log.info("WIDS stopped during shutdown")
    except Exception as e:
        log.warning("WIDS shutdown cleanup error: %s", e)

    # Stop NIDS if running
    try:
        from NIDS.nids_routes import state as nids_state
        if nids_state.is_running and nids_state.proc:
            try:
                nids_state.proc.terminate()
                nids_state.proc.wait(timeout=5)
            except Exception:
                try:
                    nids_state.proc.kill()
                except Exception:
                    pass
            nids_state.is_running = False
            nids_state.proc = None
            log.info("NIDS stopped during shutdown")
    except Exception as e:
        log.warning("NIDS shutdown cleanup error: %s", e)

    # THREAT has no background process — ThreatEngine is stateless
    try:
        log.info("THREAT module shutdown — no background process to stop")
    except Exception:
        pass

    sys.exit(0)


signal.signal(signal.SIGINT, on_signal)
signal.signal(signal.SIGTERM, on_signal)


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("\n  ✗ Must run with sudo (needs monitor mode / raw sockets / nftables)\n")
        sys.exit(1)

    init_db()
    log.info("UNetrix API starting on %s:%d", API_HOST, API_PORT)
    log.info("Dashboard: http://localhost:%d", API_PORT)

    app.run(
        host=API_HOST,
        port=API_PORT,
        debug=False,
        threaded=True,
        use_reloader=False,
    ) 
