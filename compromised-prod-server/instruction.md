Your team's jumphost has been compromised. An attacker gained SSH access, made changes to this system, and pivoted to the production server (`prod-svr`). Production HTTPS is completely down. Both systems need to be investigated and restored.

Here's what we know:

1. **SSH access to `prod-svr` is broken.** SSH is configured in `~/.ssh/config` — the host alias is `prod-svr`, user is `root`, and the private key is at `~/.ssh/id_ed25519`. Running `ssh prod-svr` should work but doesn't. It was working yesterday — something changed on this machine. Debug why SSH is failing and fix it.

2. **Persistent backdoor.** Unauthorized SSH public keys keep reappearing in `authorized_keys` even after manual removal. please find it and eliminate it completely.

3. **HTTPS is down on `prod-svr`.** Nginx on port 443 won't serve traffic. The SSL certificates isn't working. Investigate the nginx configuration and TLS setup. HTTPS requests to `prod-svr` from this jumphost must pass full TLS verification — do not use `--insecure` or disable certificate checks.

4. **Go application needs to be fixed and running.** The application source is at `/app/src/` on `prod-svr`. It should serve on port 8080 with:
   - `GET /healthz` — health check (returns 200)
   - `GET /home?name=<value>` — returns a greeting in format `hello, <name>` (requires HTTP Basic Auth with credentials `hello:1234`)

   The existing response logic in `main.go` is obfuscated and produces garbled output. A skeleton file `response.go` exists with interface definitions and TODO stubs — implement them with clean logic and wire it into `main.go`.

5. **Security requirements for the Go application:**
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
