# Instructions for agents working in this repo

This is a spec-driven API fuzzing harness (Schemathesis + ZAP + a custom
AI-semantic fuzzer, `ai-fuzzer/`). See `README.md` for the full architecture;
this file covers operational rules an agent must follow when configuring or
running it against a target service.

## Auth model: static header + optional login-derived JWT

Target APIs commonly stack two auth layers. Configure both via `.env`:

| Var | Purpose |
|-----|---------|
| `TARGET_AUTH_HEADER` / `TARGET_AUTH` | Static header sent on **every** request (spec fetch, login call, and all fuzzed requests) — e.g. `x-api-key: <key>`. |
| `TARGET_LOGIN_PATH` | Relative path (e.g. `/auth/login`) to POST `{"username","password"}` to and read a `"token"` field back. Leave blank to skip login and use only the static header. |
| `TARGET_LOGIN_USERNAME` / `TARGET_LOGIN_PASSWORD` | Credentials for the login call. |

`run-local.sh` performs the login once at the start of a run (before any
fuzz layer), and if it succeeds, sends **both** headers for the rest of the
run: the static header (e.g. `x-api-key`) plus `Authorization: Bearer <token>`.
If login fails or no `token` field comes back, the run proceeds with the
static header only and prints a warning — do not treat that as fatal, some
endpoints (health checks, docs, sometimes login itself) don't need auth at
all and will still get exercised.

Do not hand-roll a different auth flow per target: the two `.env` variables
above are the only per-API auth config this harness needs. If a target uses
a fundamentally different scheme (e.g. OAuth2 client-credentials, mTLS),
extend `run-local.sh`'s login step rather than special-casing a fuzz layer.

## Lockout hazard — verify before running

An invalid/stale value in `TARGET_AUTH` sent repeatedly can trip a target's
abuse protection. Observed on this project's own target (a local Spring Boot
service): sending a wrong `x-api-key` (copied from a different environment)
caused the app to return `403` on **all** subsequent requests — including
unauthenticated ones that worked seconds earlier — until the process was
restarted.

Before running `./run-local.sh all` (or any layer) against a target:

1. Confirm the target is reachable and the current auth values are valid
   with a single plain `curl` against an unauthenticated endpoint (spec URL
   or a health check) — do **not** probe repeatedly with headers you're
   unsure about.
2. If a login step is configured, sanity-check it once by hand too (see
   README's "Two-step auth" section for the exact request shape) before
   trusting an automated run.
3. If you get an unexpected `403` that persists across retries even without
   auth headers, stop — don't keep hammering the endpoint hoping it clears.
   Report the hypothesis (possible lockout) to the user and ask them to
   check the target's own logs/state (e.g. restart, check for a
   Redis-backed rate-limit/blocklist counter) rather than continuing to
   send requests.

## Running

```bash
./run-local.sh all            # schemathesis + ai, native (no Docker)
./run-local.sh schemathesis
./run-local.sh ai
./run.sh                      # same, via Docker Compose (needs Docker to reach TARGET_URL)
```

Use `run-local.sh` instead of `run.sh` when Docker's networking can't reach
`TARGET_URL` (common with VPNs where the host has a route but Docker's VM
doesn't).

## What NOT to do

- Don't reuse an auth value known to belong to a different environment
  against a new target "just to see" — verify it's valid for *this* target
  first (see lockout hazard above).
- Don't guess at missing credentials. If `TARGET_AUTH`/login credentials are
  unset or clearly wrong and the user hasn't supplied a working value, ask
  rather than substituting a placeholder and running anyway.
- Don't skip the fresh-spec-fetch step or reuse a stale `reports/spec-*.json`
  across runs where the target's API may have changed.
