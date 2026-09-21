// Command example demonstrates both halves of the SDK against a running issuer.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	s2s "github.com/siddharth120604/rotating-s2s/sdk"
)

const issuer = "http://localhost:8080"

func main() {
	admin := os.Getenv("S2S_SERVER_ADMIN_API_KEY")
	if admin == "" {
		admin = "dev-admin-key-change-me"
	}
	suffix := time.Now().Format("150405")
	callerName := "demo-orders-" + suffix
	targetName := "demo-billing-" + suffix

	step("registering %s and %s", callerName, targetName)
	caller := register(admin, callerName)
	target := register(admin, targetName)
	grantID := grant(admin, callerName, targetName, []string{"billing:read"})
	fmt.Printf("   grant %d: %s -> %s\n", grantID, callerName, targetName)

	validator, err := s2s.NewValidator(s2s.Config{
		IssuerURL: issuer, ClientID: target.ClientID, ClientSecret: target.ClientSecret,
	})
	must(err)

	mux := http.NewServeMux()
	mux.Handle("/invoices", validator.RequireScope("billing:read")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			who, _ := s2s.CallerFrom(r.Context())
			scopes, _ := s2s.ScopesFrom(r.Context())
			fmt.Fprintf(w, "hello %s, your scopes are %v", who, scopes)
		})))
	srv := &http.Server{Addr: "127.0.0.1:18080", Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	defer srv.Shutdown(context.Background())
	time.Sleep(200 * time.Millisecond)

	client, err := s2s.New(s2s.Config{
		IssuerURL: issuer, ClientID: caller.ClientID, ClientSecret: caller.ClientSecret,
		OnError: func(err error) { log.Printf("   [sdk] %v", err) },
	})
	must(err)
	defer client.Close()

	httpc := client.For(targetName)

	step("calling the protected endpoint (no token handling in this code)")
	fmt.Println("   " + get(httpc, "http://127.0.0.1:18080/invoices"))

	step("calling again - token is reused, no issuer round trip")
	fmt.Println("   " + get(httpc, "http://127.0.0.1:18080/invoices"))

	step("scope enforcement: a route requiring billing:write")
	mux.Handle("/refunds", validator.RequireScope("billing:write")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "should not reach here")
		})))
	fmt.Println("   " + get(httpc, "http://127.0.0.1:18080/refunds"))

	step("force-rotating the token out from under the caller")
	adminPost(admin, fmt.Sprintf("/v1/grants/%d/rotate", grantID),
		map[string]string{"reason": "sdk demo: proving 401 -> refresh -> retry"})
	fmt.Println("   the caller's token is now revoked; it does not know yet")

	step("same call again - the SDK recovers on its own")
	fmt.Println("   " + get(httpc, "http://127.0.0.1:18080/invoices"))

	step("revoking the grant entirely")
	adminPost(admin, fmt.Sprintf("/v1/grants/%d/revoke", grantID),
		map[string]string{"reason": "sdk demo: access withdrawn"})
	fmt.Println("   " + get(httpc, "http://127.0.0.1:18080/invoices"))
}

type creds struct {
	ID           uint64 `json:"id"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func step(format string, args ...any) {
	fmt.Printf("\n== "+format+"\n", args...)
}

func get(c *http.Client, url string) string {
	resp, err := c.Get(url)
	if err != nil {
		return "ERROR: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return fmt.Sprintf("HTTP %d  %s", resp.StatusCode, bytes.TrimSpace(body))
}

func register(admin, name string) creds {
	var out creds
	adminInto(admin, "/v1/services", map[string]string{"name": name}, &out)
	return out
}

func grant(admin, caller, target string, scopes []string) uint64 {
	var out struct {
		ID uint64 `json:"id"`
	}
	adminInto(admin, "/v1/grants", map[string]any{
		"caller": caller, "target": target, "scopes": scopes,
	}, &out)
	return out.ID
}

func adminPost(admin, path string, body any) { adminInto(admin, path, body, nil) }

func adminInto(admin, path string, body, out any) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, issuer+path, bytes.NewReader(raw))
	must(err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+admin)

	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("admin %s -> %d: %s", path, resp.StatusCode, b)
	}
	if out != nil {
		must(json.NewDecoder(resp.Body).Decode(out))
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
