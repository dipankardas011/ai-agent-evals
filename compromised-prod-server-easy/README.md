# Compromised Production Server (Easy)

## Overview

This is the **easy** variant of the compromised-prod-server incident response task. The jumphost has been compromised and an attacker pivoted to the production server. The agent must clean up a persistent backdoor, fix SSH key permissions, stand up nginx TLS (pre-wired cert paths are provided), and implement the Go HTTPS service from a stub.

Compared with the hard variant, this version removes:
- The `umask 0000` shell profile trap.
- X.509 forensics / AIA intermediate recovery — the full chain is pre-assembled at `/etc/nginx/certs/fullchain.crt`.
- The obfuscated `main.go` rewrite and the `greeting.go` / `DecodeSplitBase64` / `GreetingBuilder` interface contract.
- The `gorilla/mux` dependency requirement — the agent can use plain `net/http`.

The challenge is layered: each fix unlocks access to the next problem. SSH must work before you can touch prod-svr, nginx must be fixed before HTTPS works, and the Go app must be rebuilt before the endpoints return correct responses.

## Skills Tested

- **Incident response:** Removing an obfuscated, base64-encoded cron-based backdoor and the attacker's planted SSH key.
- **SSH debugging:** Diagnosing permission issues on the jumphost private key.
- **Nginx TLS & reverse proxy:** Wiring nginx to serve an existing cert chain, reverse-proxying to a local app, configuring `auth_basic` at the edge with `limit_except OPTIONS` so CORS preflight works.
- **Go development:** Writing HTTP handlers and middleware from scratch against a stub.
- **Application security:** Input validation, XSS prevention (HTML escaping), length limits, null byte rejection, HTTP security headers (`X-Content-Type-Options`, `X-Frame-Options`, HSTS), method restrictions, CORS with preflight.
- **Linux security:** Running services as non-root users via `tmux` + `su`.
- **Multi-host orchestration:** Working across jumphost and prod-svr via SSH.

## Environment Details

- **Base image:** Ubuntu 24.04
- **Containers:** 2 (jumphost `main` + `prod-svr` linked via Docker network)
- **Resources:** 2 CPUs, 4GB RAM, 10GB storage
- **Internet access:** Enabled (needed for `go mod tidy`)
- **Timeout:** Agent has 15 minutes, verifier has 3 minutes
- **Difficulty:** Easy (expert ~45m, junior ~3h)

### Planted Issues

| Layer | Location | Issue |
|-------|----------|-------|
| SSH access | jumphost `~/.ssh/id_ed25519` | Private key has `0644` perms (SSH requires `0600`) |
| Backdoor | jumphost `/etc/cron.d/apt-compat` | Cron job that re-injects attacker SSH key every minute via base64-encoded payload |
| Backdoor | jumphost `/etc/bash.bashrc` | Auto-starts cron daemon on shell login |
| Backdoor | jumphost `~/.ssh/authorized_keys` | Contains `attacker@pwned` key |
| TLS/nginx | prod-svr nginx config | `ssl_certificate` points at `server.crt` alone — must use the provided `fullchain.crt` |
| TLS/nginx | prod-svr nginx config | `proxy_pass` points to port `9090` (app listens on `8080`) |
| TLS/nginx | prod-svr nginx config | Missing semicolon after `proxy_set_header X-Real-IP` in `/home` block (nginx silently fails to start) |
| TLS/nginx | prod-svr nginx config | Suspicious `/admin` location block |
| Auth/nginx | prod-svr nginx config | No HTTP Basic Auth on `/home` — agent must configure `auth_basic` + `auth_basic_user_file` (credentials `hello:1234`) with `limit_except OPTIONS` so CORS preflight still works. Auth is enforced at the edge; the Go app must not authenticate. |
| Go app | prod-svr `/app/src/main.go` | Handlers are a stub returning 501 — agent must implement them per `instruction.md`. |
| Go app | prod-svr `/app/src/main.go` | No CORS headers, no security headers, no method restrictions, no input validation. |
| Infra security | prod-svr | App must run as `appuser`, not root. |

### TLS Layout (pre-wired)

The cert material is already in place on prod-svr:

- `/etc/nginx/certs/server.crt` — leaf
- `/etc/nginx/certs/intermediate.crt` — intermediate
- `/etc/nginx/certs/ca.crt` — root CA
- `/etc/nginx/certs/fullchain.crt` — **leaf + intermediate, ready for `ssl_certificate`**
- `/etc/nginx/certs/server.key` — private key

The jumphost also keeps the root CA at `/etc/ssl/trusted/prod-root-ca.crt`. The test suite enforces that this file stays put with the correct fingerprint — downstream systems on the jumphost depend on that exact path and filename.

## Verification

The test suite (`tests/test_outputs.py`) runs ~25 tests across these layers:

**Layer 1 — SSH Access (2 tests):**
- SSH from jumphost to prod-svr works
- SSH private key has correct permissions (`0600`)

**Layer 2 — Backdoor Removal (4 tests):**
- No attacker key in `authorized_keys` (legit operator key preserved)
- prod-svr's `authorized_keys` still contains the legit jumphost key
- No backdoor cron files exist, no cron jobs writing to `authorized_keys`
- After waiting 70 seconds, attacker key does NOT reappear

**Layer 3 — TLS/SSL (3 tests):**
- Jumphost root CA is intact at `/etc/ssl/trusted/prod-root-ca.crt` with matching fingerprint
- `nginx -t` passes on prod-svr
- SSL certificate chain includes intermediate CA (`depth=1`)

**Layer 4a — Go Application Functional (8 tests):**
- `/healthz` returns 200
- `/home` without auth returns 401
- `/home` with auth returns 200
- Response contains the `name` query parameter
- Response is clean ASCII
- Response matches format `hello, <name>`
- CORS `Access-Control-Allow-Origin` header present
- OPTIONS preflight returns 200 with CORS headers

**Layer 4b — Application Security (11 tests):**
- `X-Content-Type-Options: nosniff` header present
- `X-Frame-Options: DENY` header present
- `Strict-Transport-Security` (HSTS) header present
- Input length limit enforced (500-char name → 400)
- XSS prevention: HTML in `name` is escaped (`<script>` → `&lt;script&gt;`)
- Null bytes in `name` rejected with 400
- Non-ASCII characters in `name` rejected with 400
- `POST /home` returns 405
- `DELETE /home` returns 405
- Path traversal attempts (`/home/../etc/passwd`) return 400/404 without leaking
- Wrong basic auth credentials return 401

**Layer 4c — Code Quality & Infrastructure (2 tests):**
- Go handler unit tests pass through the full middleware chain (security headers, XSS, length limit, method restrictions). The test suite injects a `handler_test.go` that uses plain `net/http` — no router dependency is required from the agent.
- App running as `appuser`, not root.

## Running the Environment

Spin up the environment and get an interactive shell (same view as the AI agent):

```shell
harbor task start-env -p "./compromised-prod-server-easy" -i
```

With solution and tests included (not available to agent during real runs):

```shell
harbor task start-env -p "./compromised-prod-server-easy" -i -a
```

Pure agent view without solution/tests:

```shell
harbor task start-env -p "./compromised-prod-server-easy" -i --no-all
```

## Checking Results

After a run completes, results are saved under `jobs/<timestamp>/`. To inspect what failed:

```shell
# Top-level result with reward score (0.0 = fail, 1.0 = pass)
cat jobs/<timestamp>/result.json

# Per-task detailed result (agent info, timing, reward breakdown)
cat jobs/<timestamp>/compromised-prod-server-easy__<hash>/result.json

# Individual test results (which tests passed/failed with traces)
cat jobs/<timestamp>/compromised-prod-server-easy__<hash>/verifier/ctrf.json
```

The `ctrf.json` file is the most useful for debugging — it lists every test with `status: "passed"` or `status: "failed"`, and failed tests include a `trace` field with the full assertion error and stack trace.
