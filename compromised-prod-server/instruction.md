# INCIDENT — Production down, jumphost compromised

We got paged — production HTTPS is completely down and it looks like someone was on the jumphost. Security confirmed unauthorized access. We don't know the full extent yet.

Here's what we know so far:

1. **We can't SSH into `prod-svr` from this jumphost.** It was working yesterday. Something changed on this machine — figure out what and fix it.

2. **Someone keeps getting back in.** We've manually removed rogue SSH keys from `authorized_keys` multiple times but they keep reappearing within minutes. There's some kind of persistence mechanism we haven't found yet. Find it and kill it permanently.

3. **HTTPS is down on `prod-svr`.** Nginx on port 443 won't serve traffic properly. The certs aren't expired — we checked. Something else is wrong with the TLS setup. The nginx config might have other issues too.

4. **The Go application on `prod-svr` needs to be fixed and running.** Source is at `/app/src/`. It should be accessible through nginx on HTTPS. The app has a health endpoint and a greeting endpoint that takes a `name` parameter (format: `hello, <name>`). Auth is `hello:1234`. Check the source code for details — there's existing code and a skeleton file with TODOs that need to be implemented.

5. **Security team requirements:** The application must not run as root. Use proper routing and handle CORS.

Get everything working end-to-end: SSH access, clean up the compromise, HTTPS through nginx to the Go app returning correct responses.
