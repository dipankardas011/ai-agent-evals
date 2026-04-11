package main

import (
	"fmt"
	"net/http"
)

// TODO: implement the handlers and middleware described in instruction.md.
// This stub exists only so `go build` succeeds on a fresh checkout.

func handleHealth(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return next
}

func corsMiddleware(next http.Handler) http.Handler {
	return next
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
