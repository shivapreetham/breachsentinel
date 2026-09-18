# BreachSentinel

A small, self-contained attack-and-detect pipeline. It has four parts:

1. **A deliberately vulnerable multi-tenant API** (`api/app.py`) — a
   document service with JWT auth, in the style of a typical SaaS backend.
2. **An attack toolkit** (`attacks/`) — a CLI that exploits each
   vulnerability the way a real attacker would.
3. **A detection engine** (`detector/`) — reads the API's access log,
   flags the attack patterns with simple rules, and automatically blocks
   an offending IP after repeated high-severity alerts.
4. **A hardened counterpart API** (`api/app_secure.py`) — the same
   routes with every vulnerability fixed, so the toolkit can be pointed
   at it to prove each fix actually holds.

Run `python demo.py` and it walks through the whole chain end to end:
start the API, attack it four different ways, detect every attack from
the logs alone, then prove the automated block actually works by hitting
the API again afterward.

Run `python demo_secure.py` to see the same attack chain thrown at the
hardened API instead — every attack that succeeded in `demo.py` fails
here (401/403/429, no data leak), which is the actual proof that the
fixes work, not just a claim in a comment.

## Why this exists

Most "security projects" show only the attack side (find the bug, write
the exploit) or only the defense side (write detection rules against a
canned dataset). This ties them together: the same log lines produced by
real attack traffic are what the detector has to work with, so the
detection logic has to hold up against actual exploit behavior, not a
synthetic sample.

## Vulnerabilities

| # | Vulnerability | Where | Attack command |
|---|---|---|---|
| 1 | JWT `alg: none` accepted on decode (signature bypass) | `api/app.py:decode_token` | `attack.py jwt-none` |
| 2 | Weak/guessable JWT signing secret | `api/app.py` (`SECRET`) | `attack.py jwt-crack` |
| 3 | No rate limiting on `/login` | `api/app.py:login` | `attack.py brute-login` |
| 4 | Broken object-level authorization — tenant-scoped endpoints never check the caller's token against the tenant ID in the URL (IDOR/BOLA) | `api/app.py:list_documents`, `get_document` | `attack.py idor` |
| 5 | SQL injection via string-formatted query | `api/app.py:search` | `attack.py sqli` |

## Detection rules

| Rule | Logic | Severity |
|---|---|---|
| `JWT_NONE_ALG_BYPASS` | Any authenticated request where the token's `alg` header is `none` | HIGH |
| `LOGIN_BRUTE_FORCE` | 4+ failed logins for the same (IP, username) within 10s | MEDIUM, escalates to HIGH if a login then succeeds |
| `IDOR_ENUMERATION` | A caller's token is used to access 2+ tenants it doesn't belong to within 15s | HIGH |
| `SQLI_ATTEMPT` | A query parameter matches known SQL injection signatures (`' OR '1'='1`, `UNION SELECT`, `DROP TABLE`, SQL comment terminators) | HIGH |
| `RECON_SCANNING` | 5+ `404` responses from the same IP within 15s (ID/endpoint guessing, with or without a valid token) | MEDIUM |

After 2 HIGH-severity alerts from the same source IP, that IP is written
to `alerts/blocklist.json`; the API checks this file on every request and
rejects blocked IPs with `403` — a minimal example of automated response,
not just alerting.

## Remediation (`api/app_secure.py`)

Every vulnerability above has a fix in the hardened counterpart, on the
same routes so it's a direct before/after comparison:

| # | Fix | How |
|---|---|---|
| 1 | JWT `alg: none` | `jwt.decode()` always passes a fixed `algorithms=["HS256"]` allowlist — it never branches on the token's own header, so PyJWT rejects anything else |
| 2 | Weak signing secret | Read from `JWT_SECRET` env var, falling back to a random 32-byte secret per run — never a hardcoded guessable string |
| 2b | Plaintext passwords (found while hardening — not in the original vuln list) | Stored as salted hashes via Werkzeug's `generate_password_hash`/`check_password_hash` |
| 3 | No rate limiting on `/login` | In-memory sliding-window limiter, `429` after 5 attempts per (IP, username) in 10s |
| 4 | BOLA/IDOR | Every tenant-scoped route checks `token.tenant_id == path.tenant_id` (or `role == "admin"`) before returning data |
| 5 | SQL injection | `/search` uses a parameterized query instead of string-formatting the input |

Run `python demo_secure.py` to see all four attacks fail against this
version. Note the attack toolkit itself needed a small correctness fix
alongside this: `attack.py idor` originally reported *every* `200`
response as a hit, including the caller's own tenant, which made a
correctly-secured API look vulnerable in the demo output. It now decodes
the caller's own `tenant_id` from the token and only calls it IDOR when a
*foreign* tenant is actually readable.

## How this maps to production/AWS controls

None of this project runs on AWS — it's intentionally local-only — but
each piece is a hand-built version of a control a real deployment would
buy rather than build:

| This project | Production equivalent |
|---|---|
| `is_blocked()` / `blocklist.json` IP check | AWS WAF IP sets, or Shield for volumetric abuse |
| `detector.py` rule engine | GuardDuty findings / Sigma rules over a SIEM (mentioned below as the natural next step) |
| `logs/access.log` (JSONL) | CloudTrail + CloudWatch Logs |
| `JWT_SECRET` env var fallback | AWS Secrets Manager or KMS-backed Parameter Store |
| Per-tenant `role`/`tenant_id` check | IAM policy conditions / least-privilege resource policies |
| In-memory login rate limiter | API Gateway throttling or WAF rate-based rules |

## Tests

`tests/test_detector.py` covers each detection rule twice — once for the
attack pattern it should catch, once for a look-alike it shouldn't (e.g.
a benign search containing the word "or", a single foreign-tenant access
below the enumeration threshold). Rule-based detection is only as
trustworthy as its false-positive rate, so the "shouldn't fire" cases
matter as much as the "should fire" ones.

```bash
python -m unittest discover tests
```

## Running it

Requires Python 3.10+.

```bash
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt

python demo.py
```

Or run each piece by hand, in separate terminals:

```bash
python api/app.py

# in another terminal
python attacks/attack.py jwt-none
python attacks/attack.py brute-login --username bob --wordlist attacks/wordlist.txt
python attacks/attack.py idor --token <a valid JWT> --max-tenant 3 --max-doc 6
python attacks/attack.py sqli
python attacks/attack.py jwt-crack --token <a captured JWT> --wordlist attacks/wordlist.txt

# watch alerts as they happen, instead of a batch replay
python detector/detector.py --follow
```

## Design notes and limitations

- Detection here is intentionally rule-based and explainable rather than
  ML-based — for these attack patterns, a few well-chosen thresholds
  catch everything with no false-positive tuning, and the logic is easy
  to audit line by line. Anomaly-scoring or a proper SIEM (e.g. Sigma
  rules over an ELK/Splunk pipeline) would be the natural next step for
  a system handling more than a handful of signatures.
- Detection runs as a batch replay of the access log (or a `--follow`
  tail), not inline with each request — an attack sequence completes
  before it's flagged. Blocking an IP only prevents *future* requests,
  which is why the demo's step 9 exists as a separate check.
- Blocking is by source IP, which is why every attack in the demo shares
  one address (the attacker's own machine) and a block affects all
  future traffic from it, including the legitimate user in step 9. In
  production this would key off a more precise identity (session,
  account, or device fingerprint) to avoid collateral blocking behind a
  shared NAT or proxy.
- The vulnerable API is for local use only — never expose it to a
  network.
