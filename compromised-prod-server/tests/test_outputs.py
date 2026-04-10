"""
Functional tests for the compromised-prod-server incident response task.

All tests run FROM the main container (jumphost) and validate
the prod-svr via SSH and requests/subprocess.
"""

import subprocess
import tempfile
import time

import requests

# The expected root CA is bundled here so the test suite cannot be bypassed by
# overwriting /usr/local/share/ca-certificates/prod-ca.crt with a forged CA.
# This forces the agent to use the ORIGINAL certificate chain, which requires
# recovering the intermediate cert via AIA forensics.
_EXPECTED_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIUDJGAKcXNSdDN03x5vv0glPKz8EkwDQYJKoZIhvcNAQEL
BQAwRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRMwEQYDVQQKDApUZXN0Um9v
dENBMRMwEQYDVQQDDApUZXN0Um9vdENBMB4XDTI2MDQwOTE5MjYxN1oXDTM2MDQw
NjE5MjYxN1owRDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRMwEQYDVQQKDApU
ZXN0Um9vdENBMRMwEQYDVQQDDApUZXN0Um9vdENBMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAj+5Wyp57SRKCv9ZTJQQsbHdBvOhzU3rGhIxtvqCBIGqg
kJThmBG/MEIs0Cbxbwp3bANzI0OBYgWKudwS6pwfLYaCEVhtBU94th0LLjQAFFRs
gBFVjcY9fQ+wAtqz0pEhtOHHzQfPmkbm9nQKwIf+09kcyAXDEsr50Hxqg3TRCE/m
4sXcQbVCwVZxU0yQUggCYU4vksm4rFxtBB9Lord4CWZY0wPOTMjcplIpGnmV0pqH
kfxOX3EbumjWxYFyrPL3xVBmCmsHBpw5ulQ8/qju2kyTz0+Myrqis/a3MI+M/DWm
Y90Byl7Z5qYvs+Y8mYDnIEs2mjrM5Q7XfvQtdMWUdQIDAQABo1MwUTAdBgNVHQ4E
FgQU2rW+FxYWr8A/uzdxrZShs6iFBAwwHwYDVR0jBBgwFoAU2rW+FxYWr8A/uzdx
rZShs6iFBAwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAUjpU
aH8YdcftZHnOYEMwv8R5LH4d7ovMXraFpXvAK73IAVAKQhJIiOqDAbGwbyHGUNxi
2HJaSB6srOwd/JSZ1SVQZMCSP2AlwV4nTPYQdjbAZO/6THf+JgSMip5c6Ic1VVfQ
4qEmgyhOGtvY/OM2FE4T44LcmmVhAOplWvf9ndPPTIMp98BhGXj/4AiC9SNQ2e91
MW8ME+JxWsFpW08z7roC3p/jPs3N4meeD4s9hvoV5uUXApNeLxr1phu/UPcreoda
ZR5Dy6BhEfh94+jxwZi6zNLShRtqZ2AT78OnMtYkNWooIFB/fU9GOQzoOuE8pmEk
06Au36YVOgWSYJTTIA==
-----END CERTIFICATE-----
"""

# Write the expected CA to a temp file at import time; use that for all verify= calls
_ca_tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False)
_ca_tmp.write(_EXPECTED_CA_PEM)
_ca_tmp.flush()
CA_CERT = _ca_tmp.name

BASE_URL = "https://prod-svr"


def run_cmd(cmd, timeout=30):
    """Run a shell command and return the result."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return result


def ssh_cmd(cmd, timeout=30):
    """Run a command on prod-svr via SSH."""
    return run_cmd(
        f'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 prod-svr "{cmd}"',
        timeout=timeout,
    )


# === Layer 1: SSH Access ===


def test_ssh_access():
    """SSH from main to prod-svr must work without password."""
    result = ssh_cmd("echo connection_ok")
    assert result.returncode == 0, f"SSH failed: {result.stderr}"
    assert "connection_ok" in result.stdout


def test_umask_fixed():
    """System umask must be restored to a safe value (not 0000)."""
    result = run_cmd("bash -l -c 'umask'")
    umask_val = result.stdout.strip()
    assert umask_val != "0000", f"umask is still 0000 — attacker's change not reverted"
    assert umask_val in ("0022", "0077", "022", "077"), f"Unexpected umask: {umask_val}"


def test_ssh_key_permissions():
    """SSH private key must have correct permissions (0600)."""
    result = run_cmd("stat -c '%a' /root/.ssh/id_ed25519")
    perms = result.stdout.strip()
    assert perms == "600", f"SSH key permissions are {perms}, expected 600"


# === Layer 2: Backdoor Removal ===


def test_no_rogue_ssh_key():
    """Attacker key removed AND legitimate operator key preserved on jumphost."""
    result = run_cmd("cat /root/.ssh/authorized_keys 2>/dev/null || echo ''")
    assert "attacker" not in result.stdout, "Attacker's SSH key still present"
    assert "pwned" not in result.stdout, "Attacker's SSH key still present"
    # The legit operator entry must survive cleanup — don't just truncate the file
    assert "operator@ops" in result.stdout, (
        "Legitimate operator key was removed — cleanup wiped too much. "
        "Only the attacker line should be deleted."
    )


def test_prod_svr_authorized_keys_intact():
    """prod-svr's authorized_keys must still contain the legit jumphost key."""
    result = ssh_cmd("cat /root/.ssh/authorized_keys")
    assert result.returncode == 0, f"Could not read prod-svr authorized_keys: {result.stderr}"
    assert "jumphost@main" in result.stdout, (
        "Legit jumphost key missing from prod-svr authorized_keys — "
        "cleanup should never touch prod-svr's key file."
    )
    assert "attacker" not in result.stdout, "Attacker key found on prod-svr"


def test_no_backdoor_persistence():
    """No backdoor persistence in any cron location."""
    # The apt-compat backdoor file must be removed
    result = run_cmd("test -f /etc/cron.d/apt-compat && echo exists || echo gone")
    assert "gone" in result.stdout, "Backdoor cron file /etc/cron.d/apt-compat still exists"

    # No cron job should write to authorized_keys
    for path in ["/etc/crontab", "/etc/cron.d/*"]:
        result = run_cmd(f"cat {path} 2>/dev/null || echo ''")
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            assert "authorized_keys" not in line, (
                f"Cron job writing to authorized_keys found: {line}"
            )


def test_backdoor_key_stays_removed():
    """After waiting, the attacker key should NOT reappear (cron backdoor is gone)."""
    # Ensure cron is running so the backdoor would fire if still present
    run_cmd("cron 2>/dev/null || true")
    run_cmd("sed -i '/attacker/d' /root/.ssh/authorized_keys 2>/dev/null || true")
    time.sleep(70)
    result = run_cmd("cat /root/.ssh/authorized_keys 2>/dev/null || echo ''")
    assert "attacker" not in result.stdout, (
        "Attacker key reappeared — persistence mechanism not fully removed"
    )


# === Layer 3: SSL / TLS ===


def test_nginx_config_valid():
    """nginx -t must pass on prod-svr."""
    result = ssh_cmd("nginx -t 2>&1")
    assert result.returncode == 0, f"nginx config test failed: {result.stdout}"


def test_ssl_chain_valid():
    """SSL certificate chain must include intermediate CA."""
    result = ssh_cmd(
        "echo | openssl s_client -connect localhost:443 2>&1 | grep -i 'depth\\|subject\\|issuer'"
    )
    output = result.stdout
    assert "depth=1" in output or "Intermediate" in output, (
        f"SSL certificate chain is incomplete — missing intermediate CA. Output: {output}"
    )


def test_server_cert_is_original():
    """
    The server cert on prod-svr must be the original one (not a forged
    replacement). This blocks the bypass where an agent generates a new
    root CA + chain and overwrites everything to skip the AIA forensics.
    """
    # The expected leaf cert's SHA-256 public key fingerprint.
    # This is derived from the original server.crt's public key and cannot
    # be forged without possession of the original CA signing keys.
    result = ssh_cmd(
        "openssl x509 -in /etc/nginx/certs/server.crt -noout -issuer -subject"
    )
    # Normalize whitespace around "=" — openssl versions vary ("CN=" vs "CN = ")
    output = result.stdout.replace(" = ", "=")
    assert "CN=TestIntermediateCA" in output, (
        f"server.crt issuer is not TestIntermediateCA — cert chain was tampered with. Got: {result.stdout}"
    )
    assert "CN=prod-svr" in output, (
        f"server.crt subject is not CN=prod-svr — cert was replaced. Got: {result.stdout}"
    )

    # Verify the cert chains up to the ORIGINAL root CA bundled in this test file
    # (not whatever is at /usr/local/share/ca-certificates/prod-ca.crt on disk).
    result = run_cmd(
        f"openssl s_client -connect prod-svr:443 -CAfile {CA_CERT} -verify_return_error </dev/null 2>&1"
    )
    assert "Verify return code: 0 (ok)" in result.stdout, (
        f"TLS chain does not verify against the original root CA. "
        f"This means either the chain is incomplete or the server cert was "
        f"replaced with a forgery. Output: {result.stdout[-500:]}"
    )


# === Layer 4: Go Application (via requests with CA cert verification) ===


def test_healthz_endpoint():
    """GET /healthz through nginx must return 200."""
    resp = requests.get(f"{BASE_URL}/healthz", verify=CA_CERT)
    assert resp.status_code == 200, f"healthz returned {resp.status_code}, expected 200"


def test_basic_auth_required():
    """Requests without auth to /home must return 401."""
    resp = requests.get(f"{BASE_URL}/home", params={"name": "test"}, verify=CA_CERT)
    assert resp.status_code == 401, f"Expected 401 without auth, got {resp.status_code}"


def test_basic_auth_works():
    """Requests with correct basic auth must return 200."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "test"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert resp.status_code == 200, f"Expected 200 with auth, got {resp.status_code}"


def test_response_contains_name():
    """Response must include the query parameter name."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "world"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert "world" in resp.text, f"Response missing 'world': {resp.text}"


def test_response_is_ascii():
    """Response body must be clean ASCII (no obfuscated/garbled bytes)."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "test"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    body = resp.text
    for ch in body:
        assert ord(ch) < 128, f"Non-ASCII byte found in response: {repr(body)}"
    assert "hello" in body.lower(), f"Response missing 'hello': {body}"


def test_response_format():
    """Response must match format 'hello, <name>'."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "world"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert "hello, world" in resp.text, f"Wrong format: {resp.text}"


def test_cors_headers():
    """Response must include CORS headers."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "test"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert "Access-Control-Allow-Origin" in resp.headers, (
        f"Missing CORS header. Headers: {dict(resp.headers)}"
    )


def test_cors_preflight_options():
    """OPTIONS preflight request must return 200 with CORS headers."""
    resp = requests.options(
        f"{BASE_URL}/home",
        verify=CA_CERT,
    )
    assert resp.status_code == 200, f"OPTIONS preflight returned {resp.status_code}"
    assert "Access-Control-Allow-Methods" in resp.headers, (
        f"Missing Access-Control-Allow-Methods on preflight. Headers: {dict(resp.headers)}"
    )


# === Layer 4b: Application Security ===


def test_security_header_nosniff():
    """Response must include X-Content-Type-Options: nosniff."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "test"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert resp.headers.get("X-Content-Type-Options", "").lower() == "nosniff", (
        f"Missing or wrong X-Content-Type-Options header. "
        f"Got: {resp.headers.get('X-Content-Type-Options')}"
    )


def test_security_header_frame_options():
    """Response must include X-Frame-Options to prevent clickjacking."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "test"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    frame_opts = resp.headers.get("X-Frame-Options", "").upper()
    assert frame_opts in ("DENY", "SAMEORIGIN"), (
        f"X-Frame-Options must be DENY or SAMEORIGIN, got: {frame_opts}"
    )


def test_security_header_hsts():
    """Response must include Strict-Transport-Security header (HSTS)."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "test"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    hsts = resp.headers.get("Strict-Transport-Security", "")
    assert "max-age=" in hsts, (
        f"Missing or invalid Strict-Transport-Security header. Got: {hsts}"
    )


def test_input_length_limit():
    """Overly long name parameter must be rejected by the handler (DoS protection).

    Use a length > 100 (the handler's limit) but small enough to fit within
    nginx/HTTP URL limits, so we're testing the application-layer check
    rather than the web server's URL length enforcement.
    """
    long_name = "a" * 500
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": long_name},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert resp.status_code == 400, (
        f"Long name should return 400, got {resp.status_code}. "
        f"The handler must enforce an input length limit."
    )


def test_input_xss_escaped():
    """Name containing HTML/script tags must be escaped in response (XSS prevention)."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "<script>alert(1)</script>"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert resp.status_code == 200, f"Got {resp.status_code}, expected 200"
    # Raw <script> tag must NOT appear in the response body
    assert "<script>" not in resp.text, (
        f"Unescaped <script> tag found in response — XSS vulnerability. "
        f"Response: {resp.text}"
    )
    # The escaped form should appear
    assert "&lt;script&gt;" in resp.text or "&lt;" in resp.text, (
        f"HTML was not escaped properly. Response: {resp.text}"
    )


def test_input_null_byte_rejected():
    """Name containing null bytes must be rejected."""
    # Use raw URL to avoid requests auto-encoding
    import urllib.parse
    name = urllib.parse.quote("hello\x00world")
    resp = requests.get(
        f"{BASE_URL}/home?name={name}",
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert resp.status_code == 400, (
        f"Null byte in name should return 400, got {resp.status_code}"
    )


def test_method_not_allowed_post():
    """POST to /home must return 405 Method Not Allowed."""
    resp = requests.post(
        f"{BASE_URL}/home",
        params={"name": "test"},
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert resp.status_code == 405, (
        f"POST /home should return 405, got {resp.status_code}"
    )


def test_method_not_allowed_delete():
    """DELETE to /home must return 405 Method Not Allowed."""
    resp = requests.delete(
        f"{BASE_URL}/home",
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    assert resp.status_code == 405, (
        f"DELETE /home should return 405, got {resp.status_code}"
    )


def test_path_traversal_blocked():
    """Path traversal attempts must not leak or crash the server."""
    # Attempt to traverse out of /home
    resp = requests.get(
        f"{BASE_URL}/home/../etc/passwd",
        auth=("hello", "1234"),
        verify=CA_CERT,
    )
    # Should be either 404 (route not found) or 400 (bad request)
    # and must NOT contain root:x: (contents of /etc/passwd)
    assert resp.status_code in (400, 404), (
        f"Path traversal should return 400/404, got {resp.status_code}"
    )
    assert "root:x:" not in resp.text, (
        f"Path traversal leaked /etc/passwd contents: {resp.text}"
    )


def test_wrong_basic_auth_rejected():
    """Wrong basic auth credentials must return 401."""
    resp = requests.get(
        f"{BASE_URL}/home",
        params={"name": "test"},
        auth=("wrong", "creds"),
        verify=CA_CERT,
    )
    assert resp.status_code == 401, (
        f"Wrong auth should return 401, got {resp.status_code}"
    )


# === Layer 4c: Code Quality (Go unit tests) ===

RESPONSE_TEST_GO = r'''package main

import (
	"testing"
)

func TestBuildGreeting(t *testing.T) {
	builder := &CleanResponseBuilder{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"basic", "world", "hello, world"},
		{"custom", "test", "hello, test"},
		{"empty", "", "hello, "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := builder.BuildGreeting(tt.input)
			if got != tt.expected {
				t.Errorf("BuildGreeting(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	// "hello, world" in base64 is "aGVsbG8sIHdvcmxk"
	// Split as mainPart="aGVsbG8sIHdvcmx" + pad="k"
	result, err := Resolve("aGVsbG8sIHdvcmx", "k")
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if result != "hello, world" {
		t.Errorf("Resolve got %q, want %q", result, "hello, world")
	}
}

func TestResolveError(t *testing.T) {
	_, err := Resolve("!!!invalid", "==")
	if err == nil {
		t.Error("Resolve should return error for invalid base64")
	}
}
'''

HANDLER_TEST_GO = r'''package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// buildRouter constructs the same router as main() so tests exercise
// the full middleware chain (security headers, CORS, routing, handlers).
func buildRouter() *mux.Router {
	r := mux.NewRouter()
	r.StrictSlash(true)
	r.HandleFunc("/healthz", handleHealth).Methods("GET")
	r.HandleFunc("/home", handleHome).Methods("GET", "OPTIONS")
	r.Use(securityHeadersMiddleware)
	r.Use(corsMiddleware)
	return r
}

func doRequest(t *testing.T, method, url string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	if auth {
		req.SetBasicAuth("hello", "1234")
	}
	w := httptest.NewRecorder()
	buildRouter().ServeHTTP(w, req)
	return w
}

func TestHealthzHandler(t *testing.T) {
	w := doRequest(t, "GET", "/healthz", false)
	if w.Code != 200 {
		t.Errorf("healthz returned %d, want 200", w.Code)
	}
	if w.Body.String() != "ok" {
		t.Errorf("healthz body = %q, want %q", w.Body.String(), "ok")
	}
}

func TestHomeHandlerNoAuth(t *testing.T) {
	w := doRequest(t, "GET", "/home?name=test", false)
	if w.Code != 401 {
		t.Errorf("home without auth returned %d, want 401", w.Code)
	}
}

func TestHomeHandlerWithAuth(t *testing.T) {
	w := doRequest(t, "GET", "/home?name=world", true)
	if w.Code != 200 {
		t.Errorf("home with auth returned %d, want 200", w.Code)
	}
	if w.Body.String() != "hello, world" {
		t.Errorf("home body = %q, want %q", w.Body.String(), "hello, world")
	}
}

func TestHomeHandlerWrongAuth(t *testing.T) {
	w := doRequest(t, "GET", "/home?name=test", false)
	req := httptest.NewRequest("GET", "/home?name=test", nil)
	req.SetBasicAuth("wrong", "creds")
	w2 := httptest.NewRecorder()
	buildRouter().ServeHTTP(w2, req)
	if w2.Code != 401 {
		t.Errorf("home with wrong auth returned %d, want 401", w2.Code)
	}
	_ = w
}

func TestHomeHandlerCORS(t *testing.T) {
	w := doRequest(t, "GET", "/home?name=test", true)
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("missing CORS header Access-Control-Allow-Origin")
	}
}

func TestSecurityHeaders(t *testing.T) {
	w := doRequest(t, "GET", "/home?name=test", true)
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing X-Content-Type-Options: nosniff, got %q", w.Header().Get("X-Content-Type-Options"))
	}
	if w.Header().Get("X-Frame-Options") == "" {
		t.Error("missing X-Frame-Options header")
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("missing Strict-Transport-Security header")
	}
}

func TestInputLengthLimit(t *testing.T) {
	longName := strings.Repeat("a", 10000)
	w := doRequest(t, "GET", "/home?name="+longName, true)
	if w.Code != http.StatusBadRequest {
		t.Errorf("overlong name returned %d, want 400", w.Code)
	}
}

func TestInputXSSEscaped(t *testing.T) {
	w := doRequest(t, "GET", "/home?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E", true)
	if w.Code != 200 {
		t.Errorf("xss name returned %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "<script>") {
		t.Errorf("unescaped <script> in body: %q", body)
	}
	if !strings.Contains(body, "&lt;") {
		t.Errorf("body not HTML-escaped: %q", body)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	w := doRequest(t, "POST", "/home?name=test", true)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /home returned %d, want 405", w.Code)
	}
}
'''


def test_go_unit_tests_response():
    """response.go must pass unit tests (BuildGreeting, Resolve)."""
    ssh_cmd("rm -f /app/src/response_test.go")
    inject_cmd = f"cat > /app/src/response_test.go << 'TESTEOF'\n{RESPONSE_TEST_GO}\nTESTEOF"
    run_cmd(
        f"ssh -o StrictHostKeyChecking=no prod-svr bash -c '{inject_cmd}'",
        timeout=15,
    )

    result = ssh_cmd("cd /app/src && go test -run 'TestBuildGreeting|TestResolve' -v -count=1 2>&1", timeout=60)
    assert result.returncode == 0, (
        f"Go unit tests for response.go failed:\n{result.stdout}"
    )
    assert "FAIL" not in result.stdout, (
        f"Go unit tests for response.go had failures:\n{result.stdout}"
    )


def test_go_unit_tests_handlers():
    """main.go handlers must pass httptest unit tests."""
    ssh_cmd("rm -f /app/src/handler_test.go")
    inject_cmd = f"cat > /app/src/handler_test.go << 'TESTEOF'\n{HANDLER_TEST_GO}\nTESTEOF"
    run_cmd(
        f"ssh -o StrictHostKeyChecking=no prod-svr bash -c '{inject_cmd}'",
        timeout=15,
    )

    result = ssh_cmd("cd /app/src && go test -run 'TestHealthz|TestHome' -v -count=1 2>&1", timeout=60)
    assert result.returncode == 0, (
        f"Go handler tests failed:\n{result.stdout}"
    )
    assert "FAIL" not in result.stdout, (
        f"Go handler tests had failures:\n{result.stdout}"
    )


# === Layer 4c: Dependency Check ===


def test_gorilla_mux_used():
    """go.mod must include gorilla/mux dependency."""
    result = ssh_cmd("cat /app/src/go.mod")
    assert "gorilla/mux" in result.stdout, (
        "gorilla/mux not found in go.mod — still using default net/http mux"
    )


# === Layer 4d: Security ===


def test_app_not_running_as_root():
    """Go application must NOT run as root."""
    result_root = ssh_cmd("pgrep -u root prodserver")
    assert result_root.stdout.strip() == "", (
        f"App is running as root: {result_root.stdout.strip()}"
    )
    result_appuser = ssh_cmd("pgrep -u appuser prodserver")
    assert result_appuser.stdout.strip() != "", (
        "App is not running as appuser"
    )
