"""
End-to-end demo: starts the vulnerable API, runs the full attack chain
against it, runs the detector over the resulting log, and proves the
auto-block response by hitting the API again afterward.

Usage: python demo.py
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import requests

sys.stdout.reconfigure(line_buffering=True)

BASE_DIR = Path(__file__).resolve().parent
URL = "http://127.0.0.1:5000"


def reset_state():
    for p in [BASE_DIR / "logs" / "access.log", BASE_DIR / "alerts" / "alerts.jsonl",
              BASE_DIR / "alerts" / "blocklist.json"]:
        if p.exists():
            p.unlink()
    (BASE_DIR / "logs").mkdir(exist_ok=True)
    (BASE_DIR / "alerts").mkdir(exist_ok=True)


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
    print(f"\n$ python attacks/attack.py {' '.join(args)}")
    subprocess.run([sys.executable, "attacks/attack.py", *args], cwd=BASE_DIR, check=False)


def section(title):
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def main():
    reset_state()

    section("1. Starting target API")
    server = subprocess.Popen([sys.executable, "api/app.py"], cwd=BASE_DIR)
    if not wait_for_health():
        print("API failed to start.")
        server.terminate()
        return
    print("API is up at", URL)

    try:
        section("2. Alice logs in normally (legitimate baseline traffic)")
        resp = requests.post(f"{URL}/login", json={"username": "alice", "password": "password123"})
        alice_token = resp.json()["token"]
        print(f"Alice's token: {alice_token}")

        section("3. Attack: forge an alg=none token for privilege escalation")
        run_attack("jwt-none")

        section("4. Attack: brute-force bob's password")
        run_attack("brute-login", "--username", "bob", "--wordlist", "attacks/wordlist.txt")

        section("5. Attack: enumerate documents across tenants using Alice's low-priv token (IDOR)")
        run_attack("idor", "--token", alice_token, "--max-tenant", "3", "--max-doc", "6")

        section("6. Attack: SQL injection probes against /search")
        run_attack("sqli")

        section("7. Attack: crack the JWT signing secret offline, forge an admin token")
        run_attack("jwt-crack", "--token", alice_token, "--wordlist", "attacks/wordlist.txt")

        section("8. Running the detection engine over the captured log")
        subprocess.run([sys.executable, "detector/detector.py"], cwd=BASE_DIR, check=False)

        section("9. Verifying automated response (is the attacker IP now blocked?)")
        resp = requests.get(f"{URL}/tenants/1/documents", headers={"Authorization": f"Bearer {alice_token}"})
        print(f"Request from 127.0.0.1 after detection -> HTTP {resp.status_code}")
        if resp.status_code == 403:
            print("Auto-block confirmed: further requests from this IP are rejected by the API.")
        else:
            print("IP was not auto-blocked this run (alert thresholds not crossed).")

        blocklist_path = BASE_DIR / "alerts" / "blocklist.json"
        if blocklist_path.exists():
            print("\nblocklist.json:")
            print(blocklist_path.read_text(encoding="utf-8"))

    finally:
        section("10. Stopping target API")
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    main()
