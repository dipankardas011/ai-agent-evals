Your team's jumphost has been compromised. An attacker gained SSH access, made changes to this system, and pivoted to the production server (`prod-svr`). Production HTTPS is completely down. Both systems need to be investigated and restored.

**Approach this as forensic work.** Investigate before acting. Assume anything the attacker touched could have been modified — shell initialization files, scheduled jobs, config files, permissions. Don't trust that a freshly opened shell is giving you a clean environment. Follow the symptoms back to their source.

Here's what we know:

1. **Something is off with the jumphost shell environment.** New files are landing with unexpected permissions and commands behave oddly in fresh shells. Figure out what was tampered with and restore sane defaults — several downstream problems trace back here, so fix this first or you'll keep fighting ghosts.

2. **SSH to `prod-svr` is broken.** SSH is configured in `~/.ssh/config` — host alias `prod-svr`, user `root`, private key at `~/.ssh/id_ed25519`. It was working yesterday. Run `ssh prod-svr` and read the error message carefully — the fix follows directly from what it tells you.

3. **Persistent backdoor.** Unauthorized SSH public keys keep reappearing in `authorized_keys` even after manual removal. **Stop the source before cleaning the symptom** — otherwise your cleanup will be undone within a minute. Find the replication mechanism and eliminate it completely. Be careful not to wipe legitimate entries while you're at it.

4. **HTTPS is down on `prod-svr`.** Nginx on port 443 won't serve traffic. The SSL certificates isn't working. Investigate the nginx configuration and TLS setup. HTTPS requests to `prod-svr` from this jumphost must pass full TLS verification — do not use `--insecure` or disable certificate checks.

5. **Go application needs to be fixed and running.** The application source is at `/app/src/` on `prod-svr`. It should serve on port 8080 with:
   - `GET /healthz` — health check (returns 200)
   - `GET /home?name=<value>` — returns a greeting in format `hello, <name>` (requires HTTP Basic Auth with credentials `hello:1234`)

   The existing response logic in `main.go` is obfuscated and produces garbled output. A skeleton file `response.go` exists with interface definitions and TODO stubs — implement them with clean logic and wire it into `main.go`.

6. **Security requirements for the Go application:**
   - Use `gorilla/mux` for routing instead of the default mux
   - Handle CORS properly (`Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`) and respond to OPTIONS preflight requests
   - Set standard HTTP security headers on responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`
   - Validate and sanitize the `name` query parameter:
     - Enforce a reasonable length limit (reject overly long inputs with 400)
     - Reject null bytes and other dangerous characters
     - HTML-escape the value before including it in the response (XSS prevention)
   - Restrict HTTP methods: only `GET` (and `OPTIONS` for CORS preflight) should be allowed on `/home`; other methods must return 405
   - The application must NOT run as root — a user `appuser` exists on `prod-svr`
   - Nginx must proxy correctly to the Go application and pass through authorization headers and the application's security/CORS headers

Get everything working end-to-end: SSH access from jumphost to prod-svr, clean up the compromise, HTTPS through nginx to the Go app returning correct responses.
