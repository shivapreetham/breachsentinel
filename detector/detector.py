"""
BreachSentinel detection engine — reads the API's access log and flags the
attack patterns produced by attacks/attack.py using simple, explainable
rules over sliding time windows (keyed by the log's own timestamps, so batch
replay of a captured log behaves the same as watching it live).

Rules:
  JWT_NONE_ALG_BYPASS   - a request was authenticated with alg="none".
  LOGIN_BRUTE_FORCE     - many failed logins for one (ip, username) in a short window.
  IDOR_ENUMERATION      - one caller's token accessed several tenants it does not own.
  SQLI_ATTEMPT          - a query parameter matches known SQL injection signatures.

On repeated HIGH severity alerts from the same IP, the source IP is written
to alerts/blocklist.json, which the API checks on every request — a small,
closed-loop example of automated response.
"""
import argparse
import json
import re
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_PATH = BASE_DIR / "logs" / "access.log"
ALERTS_PATH = BASE_DIR / "alerts" / "alerts.jsonl"
BLOCKLIST_PATH = BASE_DIR / "alerts" / "blocklist.json"

LOGIN_FAILURE_WINDOW = 10       # seconds
LOGIN_FAILURE_THRESHOLD = 4     # failed attempts
IDOR_WINDOW = 15                # seconds
IDOR_DISTINCT_TENANT_THRESHOLD = 2  # foreign tenants touched
AUTO_BLOCK_HIGH_ALERT_THRESHOLD = 2  # HIGH alerts from one IP before auto-block

SQLI_SIGNATURES = [
    re.compile(r"'\s*or\s*'?\d*'?\s*=\s*'?\d*'?", re.IGNORECASE),
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"--\s*$"),
    re.compile(r";\s*--"),
]


class Detector:
    def __init__(self):
        self.login_failures = defaultdict(deque)   # (ip, username) -> deque[ts]
        self.tenant_access = defaultdict(deque)     # (ip, username) -> deque[(ts, path_tenant)]
        self.high_alerts_by_ip = defaultdict(int)
        self.blocked_ips = self._load_blocklist()
        self.alerts = []

    def _load_blocklist(self):
        if BLOCKLIST_PATH.exists():
            try:
                return json.loads(BLOCKLIST_PATH.read_text(encoding="utf-8")).get("blocked_ips", {})
            except json.JSONDecodeError:
                return {}
        return {}

    def _save_blocklist(self):
        BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        BLOCKLIST_PATH.write_text(
            json.dumps({"blocked_ips": self.blocked_ips}, indent=2), encoding="utf-8"
        )

    def _emit(self, rule, severity, ip, detail, evidence, ts):
        alert = {
            "id": str(uuid.uuid4()),
            "ts": ts,
            "rule": rule,
            "severity": severity,
            "source_ip": ip,
            "detail": detail,
            "evidence": evidence,
        }
        self.alerts.append(alert)
        ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ALERTS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
        print(f"[{severity}] {rule} from {ip}: {detail}")

        if severity == "HIGH":
            self.high_alerts_by_ip[ip] += 1
            if (
                self.high_alerts_by_ip[ip] >= AUTO_BLOCK_HIGH_ALERT_THRESHOLD
                and ip not in self.blocked_ips
            ):
                self.blocked_ips[ip] = {"reason": rule, "blocked_at": ts}
                self._save_blocklist()
                print(f"[AUTO-RESPONSE] {ip} blocked after {self.high_alerts_by_ip[ip]} HIGH alerts.")

    def process_line(self, line):
        line = line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return

        ts = event.get("ts", time.time())
        ip = event.get("ip", "unknown")

        if event.get("jwt_alg") == "none" and event.get("auth_valid"):
            self._emit(
                "JWT_NONE_ALG_BYPASS", "HIGH", ip,
                f"unsigned token accepted for path {event.get('path')}",
                event, ts,
            )

        if event.get("event") == "login":
            key = (ip, event.get("username"))
            if not event.get("auth_valid"):
                dq = self.login_failures[key]
                dq.append(ts)
                while dq and ts - dq[0] > LOGIN_FAILURE_WINDOW:
                    dq.popleft()
                if len(dq) >= LOGIN_FAILURE_THRESHOLD:
                    self._emit(
                        "LOGIN_BRUTE_FORCE", "MEDIUM", ip,
                        f"{len(dq)} failed logins for '{event.get('username')}' in {LOGIN_FAILURE_WINDOW}s",
                        {"username": event.get("username"), "attempts": len(dq)}, ts,
                    )
            else:
                dq = self.login_failures[key]
                if len(dq) >= LOGIN_FAILURE_THRESHOLD:
                    self._emit(
                        "LOGIN_BRUTE_FORCE_SUCCESS", "HIGH", ip,
                        f"login for '{event.get('username')}' succeeded after {len(dq)} failures",
                        {"username": event.get("username"), "prior_failures": len(dq)}, ts,
                    )
                    dq.clear()

        if event.get("event") in ("list_documents", "get_document") and event.get("auth_valid"):
            token_tenant = event.get("token_tenant")
            path_tenant = event.get("path_tenant")
            user = event.get("user")
            if token_tenant is not None and path_tenant is not None:
                key = (ip, user)
                dq = self.tenant_access[key]
                dq.append((ts, path_tenant))
                while dq and ts - dq[0][0] > IDOR_WINDOW:
                    dq.popleft()
                foreign_tenants = {t for _, t in dq if t != token_tenant}
                if len(foreign_tenants) >= IDOR_DISTINCT_TENANT_THRESHOLD:
                    self._emit(
                        "IDOR_ENUMERATION", "HIGH", ip,
                        f"user '{user}' (tenant {token_tenant}) accessed foreign tenants {sorted(foreign_tenants)}",
                        {"user": user, "own_tenant": token_tenant, "foreign_tenants": sorted(foreign_tenants)},
                        ts,
                    )
                    dq.clear()

        if event.get("event") == "search":
            q = event.get("query_param", "")
            if any(sig.search(q) for sig in SQLI_SIGNATURES):
                self._emit(
                    "SQLI_ATTEMPT", "HIGH", ip,
                    f"suspicious query parameter on /search: {q!r}",
                    {"query_param": q}, ts,
                )

    def summary(self):
        by_severity = defaultdict(int)
        for a in self.alerts:
            by_severity[a["severity"]] += 1
        print("\n--- Detection summary ---")
        print(f"Total alerts: {len(self.alerts)}")
        for sev in ("HIGH", "MEDIUM", "LOW"):
            if by_severity[sev]:
                print(f"  {sev}: {by_severity[sev]}")
        if self.blocked_ips:
            print(f"Auto-blocked IPs: {list(self.blocked_ips.keys())}")


def run_batch(path):
    detector = Detector()
    with open(path, encoding="utf-8") as f:
        for line in f:
            detector.process_line(line)
    detector.summary()


def run_follow(path):
    detector = Detector()
    print(f"[*] Tailing {path} - waiting for new events (Ctrl+C to stop) ...")
    with open(path, encoding="utf-8") as f:
        f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                detector.process_line(line)
        except KeyboardInterrupt:
            detector.summary()


def main():
    parser = argparse.ArgumentParser(description="BreachSentinel detection engine")
    parser.add_argument("--log", default=str(LOG_PATH))
    parser.add_argument("--follow", action="store_true", help="Tail the log file in real time")
    args = parser.parse_args()

    if args.follow:
        run_follow(args.log)
    else:
        if not Path(args.log).exists():
            print(f"No log file at {args.log} yet.")
            return
        run_batch(args.log)


if __name__ == "__main__":
    main()
