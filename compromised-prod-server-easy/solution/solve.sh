#!/bin/bash
set -e

echo "=== Layer 1: Fix SSH key permissions ==="

chmod 700 /root/.ssh
chmod 600 /root/.ssh/id_ed25519
chmod 644 /root/.ssh/id_ed25519.pub
chmod 600 /root/.ssh/config

echo "=== Layer 2: Remove persistent backdoor ==="

# Kill the cron backdoor: remove the dropper and stop cron so it can't fire.
rm -f /etc/cron.d/apt-compat
sed -i '/command -v cron/d' /etc/bash.bashrc
service cron stop 2>/dev/null || pkill cron || true

# Remove the attacker's SSH key from the jumphost authorized_keys.
sed -i '/attacker@pwned/d' /root/.ssh/authorized_keys

echo "=== Layer 3: Wait for prod-svr SSH ==="

for i in $(seq 1 30); do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 prod-svr "echo ok"; then
        break
    fi
    echo "Attempt $i: SSH not ready, retrying..."
    sleep 1
done

echo "=== Layer 3b: Clean any stale prodserver on prod-svr ==="
ssh -o StrictHostKeyChecking=no prod-svr 'tmux kill-server 2>/dev/null || true; pkill -x prodserver 2>/dev/null || true'

echo "=== Layer 4: Rewrite the Go application ==="

ssh -o StrictHostKeyChecking=no prod-svr bash <<'SSHEOF'
set -e
cd /app/src

cat > /app/src/main.go <<'GOEOF'
package main

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"unicode"
)

const maxNameLength = 100

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	// Authentication is enforced by nginx (HTTP Basic Auth). If a request
	// reaches this handler, it has already been authorized at the edge.

	name := r.URL.Query().Get("name")
	if name == "" {
		name = "world"
	}

	if len(name) > maxNameLength {
		http.Error(w, "name parameter too long", http.StatusBadRequest)
		return
	}

	if strings.ContainsRune(name, '\x00') {
		http.Error(w, "invalid character in name", http.StatusBadRequest)
		return
	}

	for _, c := range name {
		if c > unicode.MaxASCII {
			http.Error(w, "name must be ASCII only", http.StatusBadRequest)
			return
		}
	}

	safeName := html.EscapeString(name)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "hello, %s", safeName)
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /home", handleHome)
	mux.HandleFunc("OPTIONS /home", handleHome)

	handler := securityHeadersMiddleware(corsMiddleware(mux))

	addr := ":8080"
	fmt.Printf("Server starting on %s\n", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
GOEOF

cat > /app/src/go.mod <<'GOEOF'
module prodserver

go 1.26
GOEOF

mkdir -p /app/bin
chown -R appuser:appuser /app

cd /app/src
go mod tidy
go build -o /app/bin/prodserver .
chown appuser:appuser /app/bin/prodserver

tmux new-session -d -s prodserver "su - appuser -c '/app/bin/prodserver'"
SSHEOF

echo "=== Layer 5: Wire nginx ==="

ssh -o StrictHostKeyChecking=no prod-svr bash <<'SSHEOF'
set -e

# Create the htpasswd file nginx uses for HTTP Basic Auth on /home.
printf "hello:%s\n" "$(openssl passwd -apr1 1234)" > /etc/nginx/.htpasswd
chmod 0644 /etc/nginx/.htpasswd

cat > /etc/nginx/conf.d/default.conf <<'NGINXEOF'
server {
    listen 443 ssl;
    server_name prod-svr localhost;

    ssl_certificate /etc/nginx/certs/fullchain.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location /healthz {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /home {
        # Basic auth at the edge; OPTIONS preflight is allowed without creds.
        limit_except OPTIONS {
            auth_basic "restricted";
            auth_basic_user_file /etc/nginx/.htpasswd;
        }

        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Authorization $http_authorization;
    }
}
NGINXEOF

nginx -t
nginx -s reload || nginx
SSHEOF

echo "=== Waiting for services to stabilize ==="
sleep 3

echo "=== All fixes applied ==="
