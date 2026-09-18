"""
BreachSentinel target API — a small multi-tenant document service.

Deliberately vulnerable, for use as the attack surface in this project only:
  1. JWT "alg=none" is accepted on decode (signature bypass).
  2. Signing secret is a common/weak string (crackable from a wordlist).
  3. Tenant-scoped endpoints never check that the caller's token tenant_id
     matches the tenant_id in the URL (IDOR / broken object-level auth).
  4. /search builds SQL via string formatting (classic SQL injection).

Do not deploy this outside a local sandbox.
"""
import json
import os
import sqlite3
import time
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, request

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "api" / "data.db"
LOG_PATH = BASE_DIR / "logs" / "access.log"
BLOCKLIST_PATH = BASE_DIR / "alerts" / "blocklist.json"

SECRET = "supersecretkey123"  # intentionally weak, present in attacks/wordlist.txt

USERS = {
    "alice": {"password": "password123", "tenant_id": 1, "role": "user", "user_id": 1},
    "bob": {"password": "letmein123", "tenant_id": 2, "role": "user", "user_id": 2},
    "admin": {"password": "admin123", "tenant_id": 0, "role": "admin", "user_id": 0},
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


def log_event(**fields):
    fields["ts"] = time.time()
    fields.setdefault("ip", request.remote_addr)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(fields) + "\n")


def is_blocked(ip):
    if not BLOCKLIST_PATH.exists():
        return False
    try:
        data = json.loads(BLOCKLIST_PATH.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError:
        return False
    return ip in data.get("blocked_ips", {})


def decode_token(token):
    """Returns (payload, alg, valid). VULNERABLE: trusts the alg from the token header."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        return None, None, False
    alg = header.get("alg", "HS256")
    try:
        if alg.lower() == "none":
            # VULN: accepts unsigned tokens outright
            payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        else:
            payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        return payload, alg, True
    except jwt.InvalidTokenError:
        return None, alg, False


@app.before_request
def block_known_bad_ips():
    if is_blocked(request.remote_addr):
        log_event(path=request.path, method=request.method, status=403, event="blocked_ip")
        return jsonify({"error": "blocked"}), 403


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    user = USERS.get(username)

    if not user or user["password"] != password:
        log_event(
            path="/login",
            method="POST",
            status=401,
            event="login",
            auth_valid=False,
            username=username,
        )
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
    log_event(
        path="/login",
        method="POST",
        status=200,
        event="login",
        auth_valid=True,
        username=username,
    )
    return jsonify({"token": token})


def _auth_header_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):]


@app.route("/tenants/<int:tenant_id>/documents", methods=["GET"])
def list_documents(tenant_id):
    token = _auth_header_token()
    if not token:
        log_event(path=request.path, method="GET", status=401, event="auth_missing")
        return jsonify({"error": "missing token"}), 401

    payload, alg, valid = decode_token(token)
    if not valid:
        log_event(
            path=request.path, method="GET", status=401, event="auth_failed",
            jwt_alg=alg, auth_valid=False,
        )
        return jsonify({"error": "invalid token"}), 401

    # VULN: no check that payload["tenant_id"] == tenant_id (IDOR / BOLA)
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, title FROM documents WHERE tenant_id = ?", (tenant_id,)
    ).fetchall()
    conn.close()

    log_event(
        path=request.path, method="GET", status=200, event="list_documents",
        jwt_alg=alg, auth_valid=True,
        token_tenant=payload.get("tenant_id"), path_tenant=tenant_id,
        user=payload.get("username"),
    )
    return jsonify([{"id": r[0], "title": r[1]} for r in rows])


@app.route("/tenants/<int:tenant_id>/documents/<int:doc_id>", methods=["GET"])
def get_document(tenant_id, doc_id):
    token = _auth_header_token()
    if not token:
        log_event(path=request.path, method="GET", status=401, event="auth_missing")
        return jsonify({"error": "missing token"}), 401

    payload, alg, valid = decode_token(token)
    if not valid:
        log_event(
            path=request.path, method="GET", status=401, event="auth_failed",
            jwt_alg=alg, auth_valid=False,
        )
        return jsonify({"error": "invalid token"}), 401

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, title, body FROM documents WHERE tenant_id = ? AND id = ?",
        (tenant_id, doc_id),
    ).fetchone()
    conn.close()

    log_event(
        path=request.path, method="GET", status=200 if row else 404, event="get_document",
        jwt_alg=alg, auth_valid=True,
        token_tenant=payload.get("tenant_id"), path_tenant=tenant_id,
        user=payload.get("username"),
    )
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "title": row[1], "body": row[2]})


@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")

    # VULN: raw string formatting into SQL — classic injection point
    conn = sqlite3.connect(DB_PATH)
    query = f"SELECT id, tenant_id, title FROM documents WHERE title LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
        status = 200
    except sqlite3.Error:
        rows = []
        status = 500
    conn.close()

    log_event(path="/search", method="GET", status=status, event="search", query_param=q)
    return jsonify([{"id": r[0], "tenant_id": r[1], "title": r[2]} for r in rows]), status


if __name__ == "__main__":
    init_db()
    if LOG_PATH.exists():
        LOG_PATH.unlink()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port)
