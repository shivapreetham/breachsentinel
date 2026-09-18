# Threat model

A STRIDE pass over the system in this repo: the document API
(`api/app.py` / `api/app_secure.py`), the log it produces, and the
detector that reads that log. The attack toolkit (`attacks/`) is not a
component being modeled — it plays the attacker role on purpose.

## System and trust boundaries

```
 [ attacker / client ]
          |  HTTP (no TLS in this lab; would be terminated at a
          |  load balancer / API Gateway in production)
          v
   [ document API ]---writes--->[ logs/access.log ]
          |  reads                        |
          v  (blocklist.json)             |  reads (batch or --follow)
   [ blocklist.json ] <--writes-- [ detector.py ]
```

Trust boundaries crossed:
1. **Attacker → API.** Everything arriving here (headers, JSON body, query
   params, the JWT itself) is untrusted input.
2. **API → log file.** The log is written by the API and only read by the
   detector on this machine, so it's a lower-risk boundary here - but the
   *content* of a log line can itself be attacker-influenced (e.g. a
   query string echoed into `query_param`), which matters for whether
   the detector's parsing/regex logic can itself be abused.
3. **Detector → blocklist.json → API.** This is a feedback loop: the
   detector's output becomes an input the API trusts on every request.
   If that loop can be poisoned or bypassed, the "automated response" is
   worthless.

## Assets

- JWT signing secret (`SECRET` / `JWT_SECRET`)
- User credentials
- Tenant documents (cross-tenant confidentiality)
- Integrity of `blocklist.json` and the detector's alert stream (the
  thing enforcing consequences)

## STRIDE

| Threat | Concrete scenario in this system | Vulnerable (`app.py`) | Hardened (`app_secure.py`) |
|---|---|---|---|
| **Spoofing** | Forge an `alg=none` token claiming `role: admin` | Accepted - `decode_token` trusts the header's own `alg` | Rejected - `algorithms=["HS256"]` is fixed, never read from the token |
| **Spoofing** | Recover the weak HMAC secret offline and forge any token | Secret is a guessable hardcoded string | Secret is random per run / from `JWT_SECRET`; not in any wordlist |
| **Tampering** | Alter query semantics via `/search?q='; DROP TABLE...` | String-formatted into SQL - a real injection point | Parameterized query - input is data, never SQL syntax |
| **Tampering** | Modify the `tenant_id` claim in an otherwise-valid token | Meaningless without a matching signature once the secret is strong, but the app never checks it against the URL anyway | `_authorize_tenant()` checks the claim against the path on every request |
| **Repudiation** | Deny having sent an attack after the fact | Every event is logged with `ts` + `ip`, but the log file itself is unsigned/appendable by anything with filesystem access - fine for a local lab, not a control you'd rely on in production | Same gap - a real deployment needs write-once/centralized logging (e.g. CloudTrail-style) so the log itself can't be edited by whoever it's watching |
| **Information disclosure** | Read another tenant's documents (BOLA) | `list_documents`/`get_document` never check the caller's tenant | Authorization check on every tenant-scoped route |
| **Information disclosure** | Learn whether a username exists via different error messages | Already fine here - `/login` returns the same `401` message whether the username is unknown or the password is wrong | Same (unchanged) |
| **Information disclosure** | Leak a stack trace / query text via a verbose 500 | `/search` catches `sqlite3.Error` and returns a bare 500 - no leak, but only because that one handler happens to catch broadly; `app.run()` is never started with `debug=True` (a real risk if it were - Werkzeug's debugger is remote-code-execution-capable when exposed) | Same - worth stating explicitly rather than relying on nobody enabling debug mode later |
| **Denial of service** | Hammer `/login` to exhaust it as a resource, independent of guessing a password | No rate limiting at all | In-memory sliding-window limiter (`429` after 5/10s). Residual risk noted below |
| **Elevation of privilege** | Vertical: forge/crack a token into `role: admin` | Yes (see Spoofing rows) | Fixed by the same two changes |
| **Elevation of privilege** | Horizontal: read a peer tenant's data without any role change | Yes (BOLA) | Fixed by `_authorize_tenant()` |

## Residual risk / what the hardened version does not solve

- **The login rate limiter is in-process memory**, keyed by `(ip, username)`
  with no eviction. An attacker rotating usernames grows that dict
  unboundedly (a slow memory-exhaustion DoS), and the limit resets if the
  process restarts. Production fix: an external, TTL-backed store (Redis,
  or API Gateway/WAF throttling) instead of an in-process dict.
- **IP-based blocking and rate limiting both key on `request.remote_addr`.**
  Behind a shared NAT/proxy this both under- and over-blocks (see the
  original README's design notes). A production system would key off a
  more precise identity - session, account, or device fingerprint.
- **No TLS in this lab.** A real deployment terminates TLS before traffic
  reaches the app, or the app never listens on anything but localhost/an
  internal network - this project deliberately does the latter and says
  so (`api/app.py`'s module docstring: "never deploy this outside a local
  sandbox").
- **The log/response loop is still batch or polling (`--follow` tails the
  file), not inline with the request that triggers it** - an attack
  sequence completes before it's flagged, which is why blocking only
  affects *future* requests. See the original README for why this is an
  intentional simplification, not an oversight.
