# Architecture

BreachSentinel is deliberately structured as three independently
deployable services rather than one monolith, because the thing being
demonstrated — a detector protecting a backend, and a hardened backend
that still checks the same control plane as a second layer — only means
something if the services are actually separate processes with their own
lifecycle, not just functions calling each other in-process.

```
   attacker / attack toolkit / real traffic
              |
              |  HTTP
   -----------+------------------------------
   |                              |
   v                              v
[ api ]  (5000, vulnerable)  [ api-secure ] (5001, hardened)
   |                              |
   | writes                      | reads (defense in depth)
   v                              |
[ logs/access.log ] <--- shared filesystem --->[ alerts/blocklist.json ]
   ^                                                      ^
   | reads (batch or --follow)                            |
   +---------------- [ detector ] ------------------------+
                        writes
```

## The three services

- **`api`** — the deliberately vulnerable target (`api/app.py`). This is
  what the attack toolkit and the detector's log both come from.
- **`api-secure`** — the hardened counterpart (`api/app_secure.py`). It
  doesn't get its own detector; instead it reads the *same*
  `alerts/blocklist.json` the detector writes while watching `api`. That's
  intentional: a shared control-plane store means one detection signal
  protects every service behind it, not just the one that got attacked
  first — the same reasoning behind a WAF rule or a GuardDuty finding
  being applied fleet-wide rather than to a single instance.
- **`detector`** — runs continuously (`--follow`), independent of both
  APIs' request/response cycle. It has no HTTP endpoint of its own; it
  only reads `logs/access.log` and writes `alerts/blocklist.json`.

## Why coordination is through shared state, not a network call

None of the three services call each other's APIs. `api-secure` doesn't
ask `detector` "is this IP bad?" over HTTP - it reads a file the detector
happens to also be writing. This is a real, common pattern (a shared
database row, a shared queue, a file on a mounted volume) precisely
because it decouples the services: the detector can restart, redeploy, or
be down entirely for a while without `api`/`api-secure` needing to know
anything about its availability - they just see whatever the blocklist
said last. The tradeoff, also real, is staleness: a block only takes
effect once the detector has actually processed the relevant log lines
and written the file, not the instant the attack happens. See the main
README's "Design notes and limitations" for why that's an accepted
tradeoff here rather than an oversight.

In a cloud deployment the same shape would usually be: separate
deployables (containers/Lambdas/ECS services), coordinating through a
managed shared store (DynamoDB, S3) or an event bus (EventBridge/SQS)
instead of a bind-mounted file - see [REMEDIATION.md](REMEDIATION.md)'s
mapping table for the AWS-native equivalent of each piece.

## Running the three services together

```bash
docker compose up --build            # all three
docker compose up --build api        # just the vulnerable target
docker compose logs -f detector      # watch alerts as they happen
```

Then attack whichever one you started, from the host, with the existing
toolkit - nothing about `attacks/attack.py` changes, it just takes a
different `--url`:

```bash
python attacks/attack.py --url http://localhost:5000 jwt-none      # succeeds
python attacks/attack.py --url http://localhost:5001 jwt-none      # fails (hardened)
```

After the detector auto-blocks an attacking IP, *both* `api` and
`api-secure` will reject further requests from it with `403` - not
because `api-secure` was attacked directly, but because it shares the
same control-plane file the detector updated after watching `api`.
