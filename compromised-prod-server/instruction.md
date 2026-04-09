Your team's jumphost has been compromised. An attacker gained SSH access, made changes to this system, and pivoted to the production server (`prod-svr`). Production HTTPS is completely down. Both systems need to be investigated and restored.

Here's what we know:

1. **SSH access to `prod-svr` is broken.** The SSH private key is at `~/.ssh/id_ed25519`. Something changed on this machine that prevents SSH from working — debug and fix it. Check file permissions and shell startup files (`/etc/profile`, `/etc/bash.bashrc`) for anything the attacker may have injected.

2. **Persistent backdoor.** Unauthorized SSH public keys keep reappearing in `authorized_keys` even after manual removal. There's a persistence mechanism — likely a scheduled task with an obfuscated payload. Check `/etc/cron.d/` for suspicious files. Also check if shell startup files auto-start the scheduler. Find it and kill it permanently.

3. **HTTPS is down on `prod-svr`.** Nginx on port 443 is failing. The certs aren't expired. Look at `/etc/nginx/conf.d/default.conf` — the SSL config may be using an incomplete certificate chain (there's an intermediate cert available). The config may also have syntax errors, wrong proxy ports, or unnecessary location blocks.

4. **Go application needs to be fixed and running.** The application source is at `/app/src/` on `prod-svr`. It should serve on port 8080 with:
   - `GET /healthz` — health check (returns 200)
   - `GET /home?name=<value>` — returns a greeting in format `hello, <name>` (requires HTTP Basic Auth with credentials `hello:1234`)

   The existing response logic in `main.go` is obfuscated and produces garbled output. A skeleton file `response.go` exists with `ResponseBuilder` interface and `CleanResponseBuilder` struct — implement the TODO stubs with clean logic and wire it into `main.go` to replace the obfuscated pipeline.

5. **Security requirements:**
   - The application must use `gorilla/mux` for routing (add the dependency to `go.mod`)
   - The application must handle CORS (set `Access-Control-Allow-Origin` header)
   - The application must NOT run as root — a user `appuser` exists on `prod-svr`
   - Nginx must proxy correctly to the Go application and pass through `Authorization` headers

Get everything working end-to-end: SSH access from jumphost to prod-svr, clean up the compromise, HTTPS through nginx to the Go app returning correct responses.
