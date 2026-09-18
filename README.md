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
to `alerts/blocklist.json`. Both `api/app.py` and `api/app_secure.py`
check this file on every request and reject blocked IPs with `403` — a
minimal example of automated response, not just alerting, and a shared
control-plane store that protects a service even if it was never
attacked directly. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Remediation (`api/app_secure.py`)

Every vulnerability above has a fix in the hardened counterpart, on the
same routes so it's a direct before/after comparison. Run
`python demo_secure.py` to see every attack fail against it. See
[docs/REMEDIATION.md](docs/REMEDIATION.md) for the full fix table and how
each control maps to a production/AWS equivalent (WAF, GuardDuty, IAM,
Secrets Manager, etc.).

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

### With Docker

`api`, `api-secure`, and `detector` also run as three separate containers
coordinating through a bind-mounted `logs/`/`alerts/` — the same shape as
independently deployed services sharing a control-plane store instead of
calling each other directly. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for the full picture.

```bash
docker compose up --build

# from the host, in another terminal - same toolkit, just a different port
python attacks/attack.py --url http://localhost:5000 jwt-none      # succeeds
python attacks/attack.py --url http://localhost:5001 jwt-none      # fails (hardened)
docker compose logs -f detector                                    # watch it get flagged
```

After enough HIGH alerts, the detector blocks the attacking IP in the
shared `alerts/blocklist.json` - at which point *both* `api` and
`api-secure` reject it, even though only `api` was ever attacked
directly.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for a STRIDE pass over
the system - what each vulnerability actually threatens, what the
hardened API fixes, and what residual risk remains even after fixing it.

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
