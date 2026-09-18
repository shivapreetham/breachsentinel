"""
Remediation proof: runs the exact same attack chain from demo.py against the
hardened API (api/app_secure.py) instead, to demonstrate each fix holds.

Usage: python demo_secure.py
"""
import subprocess
import sys
import time
from pathlib import Path

import requests

sys.stdout.reconfigure(line_buffering=True)

BASE_DIR = Path(__file__).resolve().parent
URL = "http://127.0.0.1:5001"


def wait_for_health(timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"{URL}/health", timeout=1).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.3)
    return False


def run_attack(*args):
    print(f"\n$ python attacks/attack.py --url {URL} {' '.join(args)}")
    subprocess.run(
        [sys.executable, "attacks/attack.py", "--url", URL, *args], cwd=BASE_DIR, check=False
    )


def section(title):
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def main():
    section("1. Starting hardened API")
    server = subprocess.Popen([sys.executable, "api/app_secure.py"], cwd=BASE_DIR)
    if not wait_for_health():
        print("API failed to start.")
        server.terminate()
        return
    print("Hardened API is up at", URL)

    try:
        section("2. Alice logs in normally (legitimate baseline traffic)")
        resp = requests.post(f"{URL}/login", json={"username": "alice", "password": "password123"})
        alice_token = resp.json()["token"]
        print(f"Alice's token: {alice_token}")

        section("3. Attack: forge an alg=none token for privilege escalation")
        run_attack("jwt-none")
        print("Expected: 401 - fixed decode always requires HS256, never trusts the header's alg.")

        section("4. Attack: brute-force bob's password")
        run_attack("brute-login", "--username", "bob", "--wordlist", "attacks/wordlist.txt")
        print("Expected: 429s well before the wordlist reaches bob's real password (rate limited).")

        section("5. Attack: enumerate documents across tenants using Alice's low-priv token (IDOR)")
        run_attack("idor", "--token", alice_token, "--max-tenant", "3", "--max-doc", "6")
        print("Expected: no hits outside tenant 1 - tenant check now enforced on every request.")

        section("6. Attack: SQL injection probes against /search")
        run_attack("sqli")
        print("Expected: payloads are treated as literal search text, no rows leaked/errors thrown.")

        section("7. Attack: crack the JWT signing secret offline, forge an admin token")
        run_attack("jwt-crack", "--token", alice_token, "--wordlist", "attacks/wordlist.txt")
        print("Expected: secret not found - it's random per run, not the wordlist's known weak string.")

    finally:
        section("8. Stopping hardened API")
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    main()
