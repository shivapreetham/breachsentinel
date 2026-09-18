"""
BreachSentinel hardened API — same routes and shape as api/app.py, with each
vulnerability fixed. Meant to be read side-by-side with app.py and attacked
with the same attacks/attack.py toolkit (against --url http://127.0.0.1:5001)
to demonstrate that every attack that succeeded there fails here.

Fixes, one per vulnerability in app.py:
  1. JWT alg=none      -> jwt.decode() is always called with a fixed
                          algorithms=["HS256"] allowlist, so PyJWT rejects
                          any token whose header claims a different alg.
  2. Weak signing key   -> secret is read from an environment variable
                          (JWT_SECRET) with a random per-run fallback, never
                          a hardcoded guessable string. In production this
                          would come from a managed secret store (e.g. AWS
                          Secrets Manager / KMS-backed Parameter Store).
  3. Plaintext passwords -> stored as salted hashes (werkzeug's
                          generate_password_hash / check_password_hash)
                          instead of comparing raw strings.
  4. No rate limiting   -> a simple in-memory sliding-window limiter blocks
                          an IP+username pair after too many failed logins
                          in a short window. A real deployment would do this
                          at the edge (WAF/API Gateway throttling) as well.
  5. BOLA/IDOR          -> every tenant-scoped endpoint checks the caller's
                          token tenant_id against the URL's tenant_id (an
                          admin role is exempted explicitly, not by default).
  6. SQL injection      -> /search uses a parameterized query instead of
                          string-formatting user input into SQL.
"""
import os
import secrets as secrets_module
import sqlite3
import time
from collections import defaultdict, deque
from pathlib import Path

import jwt
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "api" / "data_secure.db"
LOG_PATH = BASE_DIR / "logs" / "access_secure.log"

SECRET = os.environ.get("JWT_SECRET") or secrets_module.token_hex(32)
if not os.environ.get("JWT_SECRET"):
    print("[*] JWT_SECRET not set - using a random, ephemeral secret for this run.")

LOGIN_ATTEMPT_WINDOW = 10   # seconds
LOGIN_ATTEMPT_LIMIT = 5     # attempts per (ip, username) within the window
_login_attempts = defaultdict(deque)  # (ip, username) -> deque[ts]

USERS = {
    "alice": {"password_hash": generate_password_hash("password123"), "tenant_id": 1, "role": "user", "user_id": 1},
    "bob": {"password_hash": generate_password_hash("letmein123"), "tenant_id": 2, "role": "user", "user_id": 2},
    "admin": {"password_hash": generate_password_hash("admin123"), "tenant_id": 0, "role": "admin", "user_id": 0},
}

app = Flask(__name__)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS documents")
    conn.execute(
        "CREATE TABLE documents (id INTEGER PRIMARY KEY, tenant_id INTEGER, title TEXT, body TEXT)"
    )
    seed = [
        (1, 1, "Alice Q1 Notes", "Tenant 1 internal planning notes."),
        (2, 1, "Alice Roadmap", "Tenant 1 roadmap draft."),
        (3, 2, "Bob Invoice 044", "Tenant 2 billing record."),
        (4, 2, "Bob Contract Draft", "Tenant 2 confidential contract."),
        (5, 0, "Admin Master Keys", "Tenant 0 admin-only secrets."),
    ]
    conn.executemany("INSERT INTO documents VALUES (?, ?, ?, ?)", seed)
    conn.commit()
    conn.close()


def decode_token(token):
    """FIXED: algorithms is always a fixed allowlist, never taken from the
    token's own header, so alg=none (or any non-HS256 alg) is rejected."""
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"]), True
    except jwt.InvalidTokenError:
        return None, False


def _auth_header_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):]


def _rate_limited(ip, username):
    key = (ip, username)
    dq = _login_attempts[key]
    now = time.time()
    dq.append(now)
    while dq and now - dq[0] > LOGIN_ATTEMPT_WINDOW:
        dq.popleft()
    return len(dq) > LOGIN_ATTEMPT_LIMIT


@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    ip = request.remote_addr

    if _rate_limited(ip, username):
        return jsonify({"error": "too many attempts, slow down"}), 429

    user = USERS.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401

    token = jwt.encode(
        {
            "sub": user["user_id"],
            "username": username,
            "tenant_id": user["tenant_id"],
            "role": user["role"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        SECRET,
        algorithm="HS256",
    )
    return jsonify({"token": token})


def _authorize_tenant(payload, tenant_id):
    """FIXED: BOLA/IDOR - the caller's own tenant_id must match the URL's,
    unless they hold the admin role."""
    return payload.get("role") == "admin" or payload.get("tenant_id") == tenant_id


@app.route("/tenants/<int:tenant_id>/documents", methods=["GET"])
def list_documents(tenant_id):
    token = _auth_header_token()
    if not token:
        return jsonify({"error": "missing token"}), 401

    payload, valid = decode_token(token)
    if not valid:
        return jsonify({"error": "invalid token"}), 401

    if not _authorize_tenant(payload, tenant_id):
        return jsonify({"error": "forbidden"}), 403

    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, title FROM documents WHERE tenant_id = ?", (tenant_id,)
    ).fetchall()
    conn.close()
    return jsonify([{"id": r[0], "title": r[1]} for r in rows])


@app.route("/tenants/<int:tenant_id>/documents/<int:doc_id>", methods=["GET"])
def get_document(tenant_id, doc_id):
    token = _auth_header_token()
    if not token:
        return jsonify({"error": "missing token"}), 401

    payload, valid = decode_token(token)
    if not valid:
        return jsonify({"error": "invalid token"}), 401

    if not _authorize_tenant(payload, tenant_id):
        return jsonify({"error": "forbidden"}), 403

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, title, body FROM documents WHERE tenant_id = ? AND id = ?",
        (tenant_id, doc_id),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "title": row[1], "body": row[2]})


@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")

    # FIXED: parameterized query - user input is bound, never formatted into SQL.
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, tenant_id, title FROM documents WHERE title LIKE ?", (f"%{q}%",)
    ).fetchall()
    conn.close()
    return jsonify([{"id": r[0], "tenant_id": r[1], "title": r[2]} for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001)
