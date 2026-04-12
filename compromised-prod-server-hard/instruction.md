Your team's jumphost has been compromised. An attacker got SSH access, tampered with this system, pivoted to the production server (`prod-svr`), and left artifacts on both. Production HTTPS is down. Investigate and restore end-to-end.

```
+------------------+          +-----------------------------------+
|   Jumphost       |          |   prod-svr                        |
| (compromised)    |          | (production)                      |
|                  |          |                                   |
| - You are here   |  <-----> | - Nginx (443)                     |
| - SSH keys       |          | - SSH server (22)                 |
|                  |          | - Go app behind Nginx             |
+------------------+          +-----------------------------------+
```

## Required end state

### SSH
- `ssh prod-svr` from the jumphost works without password
- The only authorized key that is able to SSH into `prod-svr` is `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9eratork3yF0rJumpH0st4ccessSREteam00001`
- make sure there is no backdoor planted aka make sure its permeantly resolved and cannot come back in future.
- Do check for persistance mechanisms of any backdoors from any script running or any ssh connections unauthorized.

### Trust anchors on the jumphost
- The root CA for for communicating in HTTPS to `prod-svr` should be in this location `/etc/ssl/trusted/prod-root-ca.crt` inside the `jumphost`. So that other tooling and downstream systems on this host depend on that path — do not move, rename, or overwrite it with a different CA. find and recover the original stuff aka fix the ssl.

### HTTPS on prod-svr
- Nginx must serve 443 with the original self-signed chain. Do not regenerate or forge any part of the chain.
- Nginx must present HTTPS requests from the jumphost to `https://prod-svr` pass standard TLS verification — no `--insecure`, no `-k`.
- The intermediate CA is no longer where it was originally kept. Attackers moved files around during the breach; recovery is part of the task.
- `/home` and `/healthz` on port 443 must reverse-proxy to the Go app on localhost:8080, preserving the app's response headers.
- HTTP Basic Auth on `/home` is enforced **at the nginx layer only**. The Go app must not perform any auth check. Credentials: `hello:1234`. `/healthz` must remain open (no auth).

### Go application
- Source code lives at `/app/src` on `prod-svr`. Keep it there.
- It ships with an obfuscated `main.go`. Rewrite it.
- Routes:
  - `GET /healthz` → 200 `ok`
  - `GET /home?name=<value>` → 200, body exactly `hello, <name>` (default name is `world`)
  - Make sure to handle `OPTIONS` methods as well.
- Response body must be pure ASCII. No multi-byte bytes.
- You may use the standard library `net/http` (or any router you like).
- `main.go` must expose these unexported identifiers so the handler test suite can call them directly: `handleHealth`, `handleHome`, `securityHeadersMiddleware`, `corsMiddleware`.

### Security requirements for the Go app
- `/home` allows only `GET` and `OPTIONS`. Any other method → 405.
- CORS: set `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers` on every response. Handle `OPTIONS` preflight properly.
- Security headers on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=...`.
- Input validation on `name`:
  - reject lengths over 100 with 400
  - reject null bytes with 400
  - reject non-ASCII characters with 400
  - HTML-escape before echoing (XSS)

### Running the Go app
- Build first. Make sure the build succeeds before proceeding. The binary name must be `prodserver`.
- The process must run as `appuser` — never root. `appuser` has no sudo and no root access. `/app/src` starts out owned by root, so permissions will need adjustment.
- Run the binary inside a `tmux` session on `prod-svr` so it survives the SSH disconnect.
- Before finishing, use curl to verify that all your endpoints return the exact expected HTTP status codes and headers from the jumphost.

> Think like a DevSecOps engineer: think before you act. The attacker's persistence mechanism will re-plant artifacts if you only do a surface-level cleanup.
