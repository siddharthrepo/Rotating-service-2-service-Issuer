// Command orders-api is a caller service: it fronts a public endpoint and
// fetches invoice data from billing-api over an authenticated s2s call.
//
// Note what is NOT in this file: no token variable, no refresh timer, no
// retry-on-401 logic. The SDK's http.Client handles all of it, so the call to
// billing-api reads exactly like any other HTTP call.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	s2s "github.com/siddharthrepo/Rotating-service-2-service-Issuer/sdk"
)

type order struct {
	ID        string `json:"id"`
	InvoiceID string `json:"invoice_id"`
	Item      string `json:"item"`
	Qty       int    `json:"qty"`
}

var orders = map[string]order{
	"ord-1": {ID: "ord-1", InvoiceID: "inv-1001", Item: "widget", Qty: 3},
	"ord-2": {ID: "ord-2", InvoiceID: "inv-1002", Item: "gadget", Qty: 1},
}

type server struct {
	billing    *http.Client
	billingURL string
}

func main() {
	addr := envOr("ORDERS_ADDR", "127.0.0.1:19002")

	// Two different things, deliberately separate:
	//   BILLING_URL     -- where billing-api listens on the network
	//   BILLING_SERVICE -- its registered identity with the issuer
	// The token is minted for the identity; the request goes to the address.
	billingURL := envOr("BILLING_URL", "http://127.0.0.1:19001")
	billingService := envOr("BILLING_SERVICE", "billing-api")

	client, err := s2s.New(s2s.Config{
		IssuerURL:    mustEnv("S2S_ISSUER_URL"),
		ClientID:     mustEnv("S2S_CLIENT_ID"),
		ClientSecret: mustEnv("S2S_CLIENT_SECRET"),
		OnError:      func(err error) { log.Printf("[orders][s2s] %v", err) },
	})
	if err != nil {
		log.Fatalf("orders-api: %v", err)
	}
	defer client.Close()

	// One line. From here on billing is an ordinary *http.Client that happens
	// to carry a valid, auto-rotating token on every request.
	srv := &server{billing: client.For(billingService), billingURL: billingURL}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	mux.HandleFunc("/orders/", srv.getOrder)
	mux.HandleFunc("/refund-check", srv.refundCheck)

	log.Printf("[orders] listening on %s, calling %s at %s", addr, billingService, billingURL)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// getOrder is public -- it is the edge of the system. Its call to billing-api
// is the service-to-service hop that the issuer secures.
func (s *server) getOrder(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/orders/")
	ord, ok := orders[id]
	if !ok {
		http.Error(w, "no such order", http.StatusNotFound)
		return
	}

	invoice, status, err := s.fetchInvoice(ord.InvoiceID)
	if err != nil {
		log.Printf("[orders] billing call failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"order": ord, "invoice": nil, "billing_error": err.Error(),
		})
		return
	}
	if status != http.StatusOK {
		log.Printf("[orders] billing returned %d", status)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"order": ord, "invoice": nil,
			"billing_status": status, "billing_body": strings.TrimSpace(string(invoice)),
		})
		return
	}

	var inv map[string]any
	_ = json.Unmarshal(invoice, &inv)
	writeJSON(w, http.StatusOK, map[string]any{"order": ord, "invoice": inv})
}

// refundCheck calls a billing route that needs a scope this service was not
// granted, demonstrating that scopes narrow access within a single grant.
func (s *server) refundCheck(w http.ResponseWriter, r *http.Request) {
	resp, err := s.billing.Post(s.billingURL+"/refunds", "application/json", nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	writeJSON(w, http.StatusOK, map[string]any{
		"billing_status": resp.StatusCode,
		"billing_body":   strings.TrimSpace(string(body)),
	})
}

func (s *server) fetchInvoice(id string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, s.billingURL+"/invoices/"+id, nil)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.billing.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("orders-api: %s is required", k)
	}
	return v
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
