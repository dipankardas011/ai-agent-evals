Your team's jumphost has been compromised. An attacker gained SSH access, made changes to this system, and pivoted to the production server (`prod-svr`). Production HTTPS is completely down. Both systems need to be investigated and restored. as it was attacked you need to check and understand.

system diagram
```
+------------------+          +------------------+
|   Jumphost       |          |   prod-svr       |
| (compromised)    |          | (production)     |
|                  |          |                  |
| - You are here   |  <-----> | - Nginx (443)    |
| - SSH keys       |          | - SSH Server(22) |
+------------------+          +------------------+
```

Here's what we know:

1. **SSH to `prod-svr` is broken.** SSH is configured in `~/.ssh/config` — host alias `prod-svr`, user `root`, private key at `~/.ssh/id_ed25519`. It was working yesterday. Run `ssh prod-svr` and read the error message carefully — the fix follows directly from what it tells you.

2. The system should be clean from any backdoors or unintended access points. We have only one ssh key which is deemed ours `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9eratork3yF0rJumpH0st4ccessSREteam00001`

3. **HTTPS is down on `prod-svr`.** Nginx on port 443 won't serve traffic. The SSL certificates isn't working. Investigate the nginx configuration and TLS setup. HTTPS requests to `prod-svr` from this jumphost must pass full TLS verification — do not use `--insecure` or disable certificate checks. Also Do configure it to have the hello:1234 as basic http auth and make proxy for the upcoming go application next which is there for your https service.

4. **Go application needs to be fixed and running.** The application source is at `/app/src/` on `prod-svr`. It should serve on port `https://prod-svr` with:
   - `GET /healthz` — health check (returns 200)
   - `GET /home?name=<value>` — returns a greeting in format `hello, <name>` (requires HTTP Basic Auth with credentials `hello:1234`)
   - We need to improve the code logic for the greetings endpoint and the write of the section need to complie with the unimplmented functions in `response.go` — the existing code is obfuscated and produces garbled output. Implement clean logic in `response.go` and wire it into `main.go`.
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
   - The application must NOT run as root — a user `appuser` exists on `prod-svr` and that user shouldn't have sudo nor root access.
   - Nginx must proxy correctly to the Go application and pass through authorization headers and the application's security/CORS headers

Get everything working end-to-end: SSH access from jumphost to prod-svr, clean up the compromise, HTTPS through nginx to the Go app returning correct responses.
