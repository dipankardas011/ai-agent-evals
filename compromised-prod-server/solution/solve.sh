#!/bin/bash
set -e

echo "=== Layer 1: Fix SSH access ==="

# Fix the tampered umask in /etc/profile.d/sys-tune.sh
sed -i 's/^umask 0000/umask 0022/' /etc/profile.d/sys-tune.sh

# Fix the SSH private key permissions (currently 0644 due to bad umask)
chmod 600 /root/.ssh/id_ed25519
chmod 700 /root/.ssh
chmod 644 /root/.ssh/id_ed25519.pub
chmod 600 /root/.ssh/config

echo "=== Layer 2: Remove persistent backdoor ==="

# Remove the base64-encoded backdoor from /etc/crontab
sed -i '/base64.*|.*sh/d' /etc/crontab

# Remove the attacker's SSH key from authorized_keys
sed -i '/attacker@pwned/d' /root/.ssh/authorized_keys

# Restart cron to apply cleaned crontab
service cron restart

echo "=== Layer 3: Wait for prod-svr SSH ==="

for i in $(seq 1 30); do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 prod-svr "echo ok"; then
        break
    fi
    echo "Attempt $i: SSH not ready, retrying..."
    sleep 1
done

echo "=== Layer 4: Fix Go application ==="

ssh -o StrictHostKeyChecking=no prod-svr bash <<'SSHEOF'
cd /app/src

# Write clean response.go implementation
cat > /app/src/response.go <<'GOEOF'
package main

import (
	"encoding/base64"
	"fmt"
)

// ResponseBuilder builds clean HTTP response bodies.
type ResponseBuilder interface {
	BuildGreeting(name string) string
}

// CleanResponseBuilder replaces the obfuscated response logic.
type CleanResponseBuilder struct{}

// BuildGreeting returns a clean ASCII greeting.
func (c *CleanResponseBuilder) BuildGreeting(name string) string {
	return fmt.Sprintf("hello, %s", name)
}

// Resolve takes encoded data and a padding string, returns the decoded result.
func Resolve(encoded, pad string) (string, error) {
	full := encoded + pad
	decoded, err := base64.StdEncoding.DecodeString(full)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
GOEOF

# Rewrite main.go to use CleanResponseBuilder and gorilla/mux
cat > /app/src/main.go <<'GOEOF'
package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != "hello" || pass != "1234" {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		name = "world"
	}

	builder := &CleanResponseBuilder{}
	payload := builder.BuildGreeting(name)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	fmt.Fprint(w, payload)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/healthz", handleHealth).Methods("GET")
	r.HandleFunc("/home", handleHome).Methods("GET", "OPTIONS")
	r.Use(corsMiddleware)

	addr := ":8080"
	fmt.Printf("Server starting on %s\n", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
GOEOF

# Update go.mod to include gorilla/mux
cat > /app/src/go.mod <<'GOEOF'
module prodserver

go 1.26

require github.com/gorilla/mux v1.8.1
GOEOF

# Download dependencies and build
cd /app/src
go mod tidy
go build -o /app/bin/prodserver .

# Set ownership for appuser
mkdir -p /app/bin
chown -R appuser:appuser /app

# Start app as appuser in a tmux session
tmux new-session -d -s prodserver "su - appuser -c '/app/bin/prodserver'"
SSHEOF

echo "=== Layer 5: Fix nginx config and SSL ==="

ssh -o StrictHostKeyChecking=no prod-svr bash <<'SSHEOF'
# Create full chain certificate (server + intermediate)
cat /etc/nginx/certs/server.crt /etc/nginx/certs/intermediate.crt > /etc/nginx/certs/fullchain.crt

# Fix the nginx config completely
cat > /etc/nginx/conf.d/default.conf <<'NGINXEOF'
server {
    listen 443 ssl;
    server_name prod-svr localhost;

    ssl_certificate /etc/nginx/certs/fullchain.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    ssl_verify_depth 2;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location /healthz {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /home {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Authorization $http_authorization;
    }
}
NGINXEOF

# Test and reload nginx
nginx -t
nginx -s reload || nginx
SSHEOF

echo "=== Waiting for services to start ==="
sleep 3

echo "=== All fixes applied ==="
