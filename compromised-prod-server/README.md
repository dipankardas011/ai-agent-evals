# Compromised Production Server

## Overview

This task simulates an incident response scenario where a jumphost has been compromised and an attacker has pivoted to the production server. The agent must investigate both machines, remove backdoors, fix broken SSH, repair nginx TLS, and get a Go application running — all end-to-end through HTTPS.

The challenge is layered: each fix unlocks access to the next problem. SSH must work before you can touch prod-svr, nginx must be fixed before HTTPS works, and the Go app must be rebuilt before the endpoints return correct responses.

## Skills Tested

- **Incident response & forensics:** Identifying attacker-planted modifications in shell startup files, cron jobs, and SSH configurations
- **SSH debugging:** Diagnosing permission issues and authentication failures
- **Persistence mechanism detection:** Finding obfuscated cron-based backdoors that use base64-encoded payloads
- **X.509 certificate forensics:** Inspecting cert extensions (AIA), tracing certificate chains across machines, building fullchain bundles, fixing nginx TLS config
- **Nginx reverse proxy setup:** Correct proxy_pass configuration, header forwarding, port matching
- **Go development:** Reading obfuscated code, implementing interfaces, adding dependencies (`gorilla/mux`), building and running binaries, writing middleware
- **Application security:** Input validation, XSS prevention (HTML escaping), length limits, null byte rejection, HTTP security headers (X-Content-Type-Options, X-Frame-Options, HSTS), method restrictions, CORS with preflight
- **Linux security:** Running services as non-root users
- **Multi-host orchestration:** Working across jumphost and prod-svr via SSH

## Environment Details

- **Base image:** Ubuntu 24.04
- **Containers:** 2 (jumphost `main` + `prod-svr` linked via Docker network)
- **Resources:** 2 CPUs, 4GB RAM, 10GB storage
- **Internet access:** Enabled (needed for `go mod tidy`)
- **Timeout:** Agent has 15 minutes, verifier has 3 minutes
- **Difficulty:** Hard (expert ~2h, junior ~8h)

### Planted Issues (5 layers)

| Layer | Location | Issue |
|-------|----------|-------|
| SSH access | jumphost `/etc/profile`, `/etc/bash.bashrc` | Obfuscated `umask 0000` causes new files (including SSH keys) to get wrong permissions |
| SSH access | jumphost `~/.ssh/id_ed25519` | Private key has `0644` perms (SSH requires `0600`) |
| Backdoor | jumphost `/etc/cron.d/apt-compat` | Cron job that re-injects attacker SSH key every minute via base64-encoded payload |
| Backdoor | jumphost `/etc/bash.bashrc` | Auto-starts cron daemon on shell login |
| Backdoor | jumphost `~/.ssh/authorized_keys` | Contains `attacker@pwned` key |
| TLS/nginx | prod-svr `/etc/nginx/certs/` | Intermediate cert is **missing** from prod-svr — must be recovered via AIA forensics (see TLS Forensics Flow below) |
| TLS/nginx | prod-svr nginx config | `ssl_certificate` points at `server.crt` alone — must be a fullchain bundle |
| TLS/nginx | prod-svr nginx config | `proxy_pass` points to port `9090` (app listens on `8080`) |
| TLS/nginx | prod-svr nginx config | Missing semicolon after `proxy_set_header X-Real-IP` in `/home` block (nginx silently fails to start) |
| TLS/nginx | prod-svr nginx config | Suspicious `/admin` location block |
| Auth/nginx | prod-svr nginx config | No HTTP Basic Auth on `/home` — agent must configure `auth_basic` + `auth_basic_user_file` (credentials `hello:1234`) with `limit_except OPTIONS` so CORS preflight still works. Auth is enforced at the edge; the Go app must not authenticate. |
| Go app | prod-svr `/app/src/main.go` | `assemblePayload()` is obfuscated — hex decode → base64 round-trip → byte substitution that corrupts output |
| Go app | prod-svr `/app/src/main.go` | Uses `net/http` default mux instead of `gorilla/mux` |
| Go app | prod-svr `/app/src/main.go` | No CORS headers set |
| Go app | prod-svr `/app/src/greeting.go` | `PlainGreetingBuilder.Build` and `DecodeSplitBase64` are unimplemented (panic stubs) |
| App security | Go handlers | `name` parameter must also reject non-ASCII input with 400 so the response body stays pure ASCII |
| Go app | prod-svr `/app/src/go.mod` | Missing `gorilla/mux` dependency |
| App security | Go handlers | No input validation — agent must add length limit, null-byte rejection, HTML-escape on `name` parameter |
| App security | Go middleware | No HTTP security headers — agent must set `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security` |
| App security | Go routing | No method restrictions — agent must return 405 for non-GET methods on `/home` |
| Infra security | prod-svr | App must run as `appuser`, not root |

### TLS Forensics Flow (intended solution path)

The TLS layer is deliberately designed as an X.509 forensics puzzle. Simply concatenating files in `/etc/nginx/certs/` on prod-svr won't work — the intermediate cert isn't there. The jumphost doesn't have it either. During the breach, the attacker relocated the intermediate to a hidden path under prod-svr's `/var/tmp`. The agent must:

1. **Observe HTTPS is broken** — either nginx won't start (syntax error) or the SSL handshake fails (after fixing syntax). `curl https://prod-svr/healthz` fails with a verification error.

2. **Inspect the server cert:**
   ```
   openssl x509 -in /etc/nginx/certs/server.crt -noout -text
   ```
   The `Issuer` is `TestIntermediateCA` but only `ca.crt` (TestRootCA) is present in the certs directory. The chain is incomplete.

3. **Find the AIA extension in the server cert** — the Authority Information Access extension tells verifiers where to fetch the issuer's certificate. Combined with the breach context, this is the breadcrumb.

4. **Recon for attacker-planted files on prod-svr** — dotfiles, unusual extensions, backdated mtimes under `/var/tmp`, `/opt`, `/tmp`:
   ```
   find /var/tmp /opt /tmp -type f -name '.*' -o -name '*.old' 2>/dev/null
   # /var/tmp/.cache/._x509_bundle.old   ← planted intermediate
   ```
   Verify it's actually the issuing cert:
   ```
   openssl x509 -in /var/tmp/.cache/._x509_bundle.old -noout -subject -issuer
   # subject = CN=TestIntermediateCA
   # issuer  = CN=TestRootCA
   ```

5. **Copy it into the nginx certs dir and build the fullchain bundle:**
   ```
   cp /var/tmp/.cache/._x509_bundle.old /etc/nginx/certs/intermediate.crt
   cat server.crt intermediate.crt > fullchain.crt
   ```

6. **Update nginx config** to use `fullchain.crt` instead of `server.crt`, and reload.

This layer tests whether the agent can read X.509 extensions, interpret AIA metadata, reason about attacker persistence patterns, and hunt for planted artifacts. A naive agent that tries to regenerate the chain locally will hit the "server cert is original" test and fail.

The jumphost keeps its own copy of the **root CA** (not the intermediate) at `/etc/ssl/trusted/prod-root-ca.crt`. The test suite enforces that this file stays put with the correct fingerprint — downstream systems on the jumphost depend on that exact path and filename.

## Verification

The test suite (`tests/test_outputs.py`) runs 35 tests across 4 layers:

**Layer 1 — SSH Access (4 tests):**
- SSH from jumphost to prod-svr works
- System umask is restored to a safe value (not `0000`)
- Newly created files are not world-writable
- SSH private key has correct permissions (`0600`)

**Layer 2 — Backdoor Removal (4 tests):**
- No attacker key in `authorized_keys` (legit operator key preserved)
- prod-svr's `authorized_keys` still contains the legit jumphost key
- No backdoor cron files exist, no cron jobs writing to `authorized_keys`
- After waiting 70 seconds, attacker key does NOT reappear

**Layer 3 — TLS/SSL (4 tests):**
- Jumphost root CA is intact at `/etc/ssl/trusted/prod-root-ca.crt` with matching fingerprint
- `nginx -t` passes on prod-svr
- SSL certificate chain includes intermediate CA (`depth=1`)
- Server cert is the original (not a forged replacement) — verifies against bundled root CA

**Layer 4a — Go Application Functional (8 tests):**
- `/healthz` returns 200
- `/home` without auth returns 401
- `/home` with auth returns 200
- Response contains the `name` query parameter
- Response is clean ASCII (no garbled bytes)
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

**Layer 4c — Code Quality & Infrastructure (4 tests):**
- Go unit tests pass for `greeting.go` (`PlainGreetingBuilder.Build`, `DecodeSplitBase64`, ASCII-only output)
- Go unit tests pass for handlers through full router (security headers, XSS, length limit, method restrictions)
- `gorilla/mux` in `go.mod`
- App running as `appuser`, not root

## Running the Environment

Spin up the environment and get an interactive shell (same view as the AI agent):

```shell
harbor task start-env -p "./compromised-prod-server" -i
```

With solution and tests included (not available to agent during real runs):

```shell
harbor task start-env -p "./compromised-prod-server" -i -a
```

Pure agent view without solution/tests:

```shell
harbor task start-env -p "./compromised-prod-server" -i --no-all
```

## Checking Results

After a run completes, results are saved under `jobs/<timestamp>/`. To inspect what failed:

```shell
# Top-level result with reward score (0.0 = fail, 1.0 = pass)
cat jobs/<timestamp>/result.json

# Per-task detailed result (agent info, timing, reward breakdown)
cat jobs/<timestamp>/compromised-prod-server__<hash>/result.json

# Individual test results (which tests passed/failed with traces)
cat jobs/<timestamp>/compromised-prod-server__<hash>/verifier/ctrf.json
```

The `ctrf.json` file is the most useful for debugging — it lists every test with `status: "passed"` or `status: "failed"`, and failed tests include a `trace` field with the full assertion error and stack trace.

Example: to quickly see which tests failed in a run:

```shell
cat jobs/2026-04-09__23-59-10/compromised-prod-server__*/verifier/ctrf.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for t in data['results']['tests']:
    if t['status'] == 'failed':
        print(f\"FAILED: {t['name']}\")
        print(f\"  {t.get('message', '')}\")
"
```

```shell
export OPENAI_API_BASE="http://192.168.1.18:8000/v1"
export OPENAI_API_KEY="local-dummy-key"
harbor run -p "./compromised-prod-server" \
    --agent terminus-2 \
    --model custom_openai/Qwen3.5-9B-Q5_K_M.gguf \
    --ak 'model_info:dict={"max_input_tokens": 131072, "max_output_tokens": 131072}'
```

```
./job-results.sh jobs/2026-04-10__00-33-08/result.json
```
