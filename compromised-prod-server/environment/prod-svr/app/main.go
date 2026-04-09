package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
)

func assemblePayload(input string) string {
	leftHex := "68656c6c"
	rightHex := "6f2c20"

	leftBytes, _ := hex.DecodeString(leftHex)
	rightBytes, _ := hex.DecodeString(rightHex)

	merged := append(leftBytes, rightBytes...)
	merged = append(merged, []byte(input)...)

	encoded := base64.StdEncoding.EncodeToString(merged)

	if len(encoded) < 2 {
		return ""
	}
	mainPart := encoded[:len(encoded)-1]
	pad := string(encoded[len(encoded)-1])

	reconstructed := mainPart + pad
	decoded, err := base64.StdEncoding.DecodeString(reconstructed)
	if err != nil {
		return "DECODE_ERROR"
	}

	result := []byte(string(decoded))
	subst := map[byte]byte{
		'h': 0xC3, 'e': 0xA9, 'l': 0x6C, 'o': 0x6F,
	}
	for i := 0; i < len(result) && i < 5; i++ {
		if replacement, ok := subst[result[i]]; ok {
			result[i] = replacement
			break
		}
	}

	return string(result)
}

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

	payload := assemblePayload(name)

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, payload)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/home", handleHome)

	addr := ":8080"
	fmt.Printf("Server starting on %s\n", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
