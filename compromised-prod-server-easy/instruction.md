Your team's jumphost has been compromised. An attacker got SSH access, planted a persistent backdoor, pivoted to the production server (`prod-svr`), and left the HTTPS stack in a broken, unimplemented state. Investigate, clean up, and restore end-to-end.

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
- `ssh prod-svr` from the jumphost works without password.
- The only authorized key that is able to SSH into `prod-svr` is `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9eratork3yF0rJumpH0st4ccessSREteam00001`.
- Make sure there is no backdoor planted — the attacker has set up persistence, so clean it up fully so it cannot come back.

### HTTPS on prod-svr
TLS material is already on disk on `prod-svr` — no forensics required. Inspect the existing nginx config and the certs directory it references to see what's provided (leaf, intermediate, root, key, and a pre-assembled full chain).

- Nginx must serve 443 with the provided chain. Do not regenerate or forge any part of it.
- HTTPS requests from the jumphost to `https://prod-svr` must pass standard TLS verification — no `--insecure`, no `-k` check for the certs.
- `/home` and `/healthz` on port 443 must reverse-proxy to the Go app on `localhost:8080`, preserving the app's response headers.
- HTTP Basic Auth on `/home` is enforced **at the nginx layer only**. The Go app must not perform any auth check. Credentials: `hello:1234`. `/healthz` must remain open (no auth). `OPTIONS` preflight on `/home` must also be allowed without credentials so CORS works.

### Go application
- Source code lives at `/app/src` on `prod-svr`. Keep it there.
- A stub `main.go` is provided — it compiles but the handlers return 501. Rewrite it.
- Routes:
  - `GET /healthz` → 200 `ok`
  - `GET /home?name=<value>` → 200, body exactly `hello, <name>` (default name is `world`)
- Response body must be pure ASCII. No multi-byte bytes.
- You may use the standard library `net/http` (or any router you like). No specific dependency is required.
- `main.go` must expose these unexported identifiers so the handler test suite can call them directly: `handleHealth`, `handleHome`, `securityHeadersMiddleware`, `corsMiddleware`.

### Security requirements for the Go app
- `/home` allows only `GET` and `OPTIONS`. Any other method → 405.
- CORS: set `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, and handle the `OPTIONS` preflight with a 200 response (no auth required on preflight).
- Security headers on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=...`. only for the backend
- Input validation on `name`:
  - reject lengths over 100 with 400
  - reject null bytes with 400
  - reject non-ASCII characters with 400
  - HTML-escape before echoing (XSS)

### Running the Go app
- Build first. The binary name must be `prodserver`.
- The process must run as `appuser` — never root. `appuser` has no sudo and no root access. `/app/src` starts out owned by root, so permissions will need adjustment.
- Run the binary inside a `tmux` session on `prod-svr` so it survives the SSH disconnect.

> Think like a DevSecOps engineer: deal with the backdoor *first*, then stand the service back up. The attacker's persistence mechanism will re-plant artifacts if you only do a surface-level cleanup.
