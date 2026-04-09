# Incident Report: Compromised Jumphost & Production Server

## Situation

Your team's jumphost has been compromised. An attacker gained SSH access and made changes to this system before pivoting to the production server (`prod-svr`). Both systems need to be investigated and restored.

## What We Know

- **SSH access to `prod-svr` is failing.** The SSH private key is at `~/.ssh/id_ed25519`. Debug why SSH is not working and fix it.
- **Persistence mechanism detected.** Unauthorized SSH public keys keep reappearing in the authorized_keys file even after manual removal. Find the persistence mechanism and eliminate it completely.
- **Production HTTPS service is down.** The nginx service on `prod-svr` (port 443) is returning SSL handshake errors. The SSL certificates are not expired. Diagnose and fix the TLS configuration.
- **Go application needs to be fixed and built.** The application source code is at `/app/src/` on `prod-svr`. It should serve on port 8080 with the following endpoints:
  - `GET /healthz` — health check (returns 200)
  - `GET /home?name=<value>` — returns a greeting with the provided name, format: `hello, <name>`
  - All endpoints under `/home` require HTTP Basic Auth with credentials `hello:1234`
- **Code quality requirement.** The existing response logic in `main.go` is unnecessarily obfuscated. A skeleton file `response.go` exists with interface definitions. Implement the TODO stubs in `response.go` with clean, readable logic and wire it into `main.go` to replace the obfuscated pipeline.
- **Security requirements:**
  - The application must use `gorilla/mux` for routing instead of the default `net/http` mux (to support proper path validation).
  - The application must handle CORS properly (set `Access-Control-Allow-Origin` header).
  - The application must NOT run as root. A user `appuser` exists on `prod-svr`.
- **nginx must proxy correctly** to the Go application and pass through CORS and Authorization headers.

## Your Task

Investigate both the jumphost and `prod-svr`. Find and fix all issues. Restore full service so that HTTPS requests through nginx to the Go application work correctly.
