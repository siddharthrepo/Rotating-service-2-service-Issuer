// Command billing-api is a target service: it accepts calls from other
// services and verifies them through the s2s issuer.
//
// Every route under /invoices requires a valid token minted for billing-api
// AND the billing:read scope. There is no shared secret with the caller
// anywhere in this file.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	s2s "github.com/siddharthrepo/Rotating-service-2-service-Issuer/sdk"
)

type invoice struct {
	ID       string  `json:"id"`
	Customer string  `json:"customer"`
	AmountP  int64   `json:"amount_paise"`
	Status   string  `json:"status"`
	ServedTo string  `json:"served_to"`
	Currency string  `json:"currency"`
	Tax      float64 `json:"tax_rate"`
}

var invoices = map[string]invoice{
	"inv-1001": {ID: "inv-1001", Customer: "acme-corp", AmountP: 4599900, Status: "paid", Currency: "INR", Tax: 0.18},
	"inv-1002": {ID: "inv-1002", Customer: "globex", AmountP: 1250000, Status: "pending", Currency: "INR", Tax: 0.18},
}

func main() {
	addr := envOr("BILLING_ADDR", "127.0.0.1:19001")

	validator, err := s2s.NewValidator(s2s.Config{
		IssuerURL:    mustEnv("S2S_ISSUER_URL"),
		ClientID:     mustEnv("S2S_CLIENT_ID"),
		ClientSecret: mustEnv("S2S_CLIENT_SECRET"),
		OnError:      func(err error) { log.Printf("[billing][s2s] %v", err) },
	})
	if err != nil {
		log.Fatalf("billing-api: %v", err)
	}

	mux := http.NewServeMux()

	// Public: no token required, so orchestration can check liveness.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	// Protected: a valid token for billing-api, carrying billing:read.
	mux.Handle("/invoices/", validator.RequireScope("billing:read")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, _ := s2s.CallerFrom(r.Context())

			id := strings.TrimPrefix(r.URL.Path, "/invoices/")
			inv, ok := invoices[id]
			if !ok {
				http.Error(w, "no such invoice", http.StatusNotFound)
				return
			}
			// The caller identity is verified by the issuer, not claimed by
			// the caller -- so it is safe to log, authorise on, and return.
			inv.ServedTo = caller
			log.Printf("[billing] served %s to %s", id, caller)

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(inv)
		})))

	// Also protected, but needs a scope this demo's grant does not include.
	mux.Handle("/refunds", validator.RequireScope("billing:write")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"refunded":true}`)
		})))

	log.Printf("[billing] listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("billing-api: %s is required", k)
	}
	return v
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
