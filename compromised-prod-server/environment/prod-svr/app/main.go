package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
)

// assemblePayload constructs the response string using a multi-stage pipeline.
// Do NOT modify the encoding logic directly — rewrite it cleanly in response.go.
func assemblePayload(input string) string {
	// Stage 1: hex-encoded fragments
	leftHex := "68656c6c"   // <-- part 1
	rightHex := "6f2c20"    // <-- part 2

	// Stage 2: decode hex to bytes
	leftBytes, _ := hex.DecodeString(leftHex)
	rightBytes, _ := hex.DecodeString(rightHex)

	// Stage 3: merge and encode to base64
	merged := append(leftBytes, rightBytes...)
	merged = append(merged, []byte(input)...)

	// Stage 4: re-encode as base64, then mangle the padding
	encoded := base64.StdEncoding.EncodeToString(merged)

	// Stage 5: strip last char of base64, store separately
	if len(encoded) < 2 {
		return ""
	}
	mainPart := encoded[:len(encoded)-1]
	pad := string(encoded[len(encoded)-1])

	// Stage 6: reconstruct and decode
	reconstructed := mainPart + pad
	decoded, err := base64.StdEncoding.DecodeString(reconstructed)
	if err != nil {
		return "DECODE_ERROR"
	}

	// Stage 7: apply a substitution cipher on the first 5 bytes
	result := []byte(string(decoded))
	subst := map[byte]byte{
		'h': 0xC3, 'e': 0xA9, 'l': 0x6C, 'o': 0x6F,
	}
	for i := 0; i < len(result) && i < 5; i++ {
		if replacement, ok := subst[result[i]]; ok {
			result[i] = replacement
			break // only replace first occurrence
		}
	}

	return string(result)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	// Basic auth check
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

	// Use the obfuscated pipeline to generate response
	payload := assemblePayload(name)

	// No CORS headers set (bug: CORS is missing)

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, payload)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/home", handleHome)

	// Intentionally binding to all interfaces
	addr := ":8080"
	fmt.Printf("Server starting on %s\n", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
