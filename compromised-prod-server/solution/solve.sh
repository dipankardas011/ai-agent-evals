#!/bin/bash
set -e

echo "=== Layer 1: Fix SSH access ==="

# Fix the obfuscated umask in /etc/profile and /etc/bash.bashrc
sed -i '/_m=uma/d' /etc/profile
sed -i '/_m=uma/d' /etc/bash.bashrc

# Set correct umask for this session
umask 0022

# Fix the SSH private key permissions
chmod 600 /root/.ssh/id_ed25519
chmod 700 /root/.ssh
chmod 644 /root/.ssh/id_ed25519.pub
chmod 600 /root/.ssh/config

echo "=== Layer 2: Remove persistent backdoor ==="

# Remove the cron backdoor from /etc/cron.d/apt-compat
rm -f /etc/cron.d/apt-compat

# Remove the attacker's SSH key from authorized_keys
sed -i '/attacker@pwned/d' /root/.ssh/authorized_keys

# Remove cron auto-start from bashrc
sed -i '/command -v cron/d' /etc/bash.bashrc

# Stop cron
service cron stop 2>/dev/null || pkill cron || true

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

cat > /app/src/response.go <<'GOEOF'
package main

import (
	"encoding/base64"
	"fmt"
)

type ResponseBuilder interface {
	BuildGreeting(name string) string
}

type CleanResponseBuilder struct{}

func (c *CleanResponseBuilder) BuildGreeting(name string) string {
	return fmt.Sprintf("hello, %s", name)
}

func Resolve(encoded, pad string) (string, error) {
	full := encoded + pad
	decoded, err := base64.StdEncoding.DecodeString(full)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
GOEOF

cat > /app/src/main.go <<'GOEOF'
package main

import (
	"fmt"
	"html"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

const maxNameLength = 100

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

	// Length limit (DoS protection)
	if len(name) > maxNameLength {
		http.Error(w, "name parameter too long", http.StatusBadRequest)
		return
	}

	// Null byte rejection
	if strings.ContainsRune(name, '\x00') {
		http.Error(w, "invalid character in name", http.StatusBadRequest)
		return
	}

	// HTML-escape the name to neutralize XSS / injection attempts
	safeName := html.EscapeString(name)

	builder := &CleanResponseBuilder{}
	payload := builder.BuildGreeting(safeName)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, payload)
}

// securityHeadersMiddleware adds baseline HTTP security headers to every response.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers and handles preflight requests.
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
	r.StrictSlash(true)
	r.HandleFunc("/healthz", handleHealth).Methods("GET")
	r.HandleFunc("/home", handleHome).Methods("GET", "OPTIONS")
	r.Use(securityHeadersMiddleware)
	r.Use(corsMiddleware)

	addr := ":8080"
	fmt.Printf("Server starting on %s\n", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
GOEOF

cat > /app/src/go.mod <<'GOEOF'
module prodserver

go 1.26

require github.com/gorilla/mux v1.8.1
GOEOF

cd /app/src
go mod tidy
go build -o /app/bin/prodserver .

mkdir -p /app/bin
chown -R appuser:appuser /app

tmux new-session -d -s prodserver "su - appuser -c '/app/bin/prodserver'"
SSHEOF

echo "=== Layer 5: Fix nginx config and SSL ==="

# Copy the intermediate cert from jumphost to prod-svr
# (discovered via AIA extension in server cert: file:///usr/local/share/ca-certificates/intermediate-ca.crt)
scp -o StrictHostKeyChecking=no /usr/local/share/ca-certificates/intermediate-ca.crt prod-svr:/etc/nginx/certs/intermediate.crt

ssh -o StrictHostKeyChecking=no prod-svr bash <<'SSHEOF'
cat /etc/nginx/certs/server.crt /etc/nginx/certs/intermediate.crt > /etc/nginx/certs/fullchain.crt

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

nginx -t
nginx -s reload || nginx
SSHEOF

echo "=== Waiting for services to start ==="
sleep 3

echo "=== All fixes applied ==="
