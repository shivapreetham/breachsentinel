# Remediation

Every vulnerability in the main [README](../README.md) has a fix in the
hardened counterpart (`api/app_secure.py`), on the same routes so it's a
direct before/after comparison:

| # | Fix | How |
|---|---|---|
| 1 | JWT `alg: none` | `jwt.decode()` always passes a fixed `algorithms=["HS256"]` allowlist — it never branches on the token's own header, so PyJWT rejects anything else |
| 2 | Weak signing secret | Read from `JWT_SECRET` env var, falling back to a random 32-byte secret per run — never a hardcoded guessable string |
| 2b | Plaintext passwords (found while hardening — not in the original vuln list) | Stored as salted hashes via Werkzeug's `generate_password_hash`/`check_password_hash` |
| 3 | No rate limiting on `/login` | In-memory sliding-window limiter, `429` after 5 attempts per (IP, username) in 10s |
| 4 | BOLA/IDOR | Every tenant-scoped route checks `token.tenant_id == path.tenant_id` (or `role == "admin"`) before returning data |
| 5 | SQL injection | `/search` uses a parameterized query instead of string-formatting the input |
| 6 | No defense-in-depth against a known-bad source | Also checks `alerts/blocklist.json`, the same file the detector writes to when watching the *vulnerable* API — see [ARCHITECTURE.md](ARCHITECTURE.md) |

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
| `detector.py` rule engine | GuardDuty findings / Sigma rules over a SIEM (see the main README's design notes) |
| `logs/access.log` (JSONL) | CloudTrail + CloudWatch Logs |
| `JWT_SECRET` env var fallback | AWS Secrets Manager or KMS-backed Parameter Store |
| Per-tenant `role`/`tenant_id` check | IAM policy conditions / least-privilege resource policies |
| In-memory login rate limiter | API Gateway throttling or WAF rate-based rules |
| `docker-compose.yml`'s three independent services + shared file state | Separate deployables (ECS services/Lambdas) coordinating through a shared store (DynamoDB/S3) or event bus (EventBridge/SQS) instead of a bind-mounted file |
