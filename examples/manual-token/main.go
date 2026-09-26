// Command manual-token shows the alternative to client.For(): fetching the
// token yourself with client.Token() and attaching it by hand.
//
// Use this when there is no http.RoundTripper to hook -- gRPC metadata, Kafka
// headers, a queue message -- or simply when you would rather see the token in
// your own code than have a transport attach it.
//
// The cost is visible below: everything client.For() does for free, you now
// write. Compare fetchWithFor() and fetchWithToken() side by side.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	s2s "github.com/siddharthrepo/Rotating-service-2-service-Issuer/sdk"
)

func main() {
	cfg := s2s.Config{
		IssuerURL:    mustEnv("S2S_ISSUER_URL"),
		ClientID:     mustEnv("S2S_CLIENT_ID"),
		ClientSecret: mustEnv("S2S_CLIENT_SECRET"),
		OnError:      func(err error) { log.Printf("[s2s] %v", err) },
	}
	target := mustEnv("TARGET_SERVICE")
	url := mustEnv("TARGET_URL")

	client, err := s2s.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("── 1. client.Token(): fetch the token yourself ──")
	token, err := client.Token(ctx, target)
	if err != nil {
		log.Fatalf("could not get a token for %q: %v", target, err)
	}
	fmt.Printf("   token: %s...\n", token[:28])
	fmt.Println("   (cached after this; the background refresher keeps it fresh)")

	fmt.Println("\n── 2. attach it and call ──")
	status, body, err := fetchWithToken(ctx, client, target, url)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   HTTP %d  %s\n", status, truncate(body, 120))

	fmt.Println("\n── 3. the same call via client.For(), for comparison ──")
	status, body, err = fetchWithFor(ctx, client, target, url)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   HTTP %d  %s\n", status, truncate(body, 120))
}

// fetchWithToken is the manual path. Note what has to be written out: getting
// the token, setting the header, and -- the part people forget -- recovering
// from a force-rotate by re-fetching and replaying the request.
func fetchWithToken(ctx context.Context, client *s2s.Client, target, url string) (int, string, error) {
	do := func(token string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultClient.Do(req)
	}

	token, err := client.Token(ctx, target)
	if err != nil {
		return 0, "", err
	}

	resp, err := do(token)
	if err != nil {
		return 0, "", err
	}

	// Force-rotate recovery, by hand. client.For() does this for you.
	if resp.StatusCode == http.StatusUnauthorized &&
		strings.Contains(resp.Header.Get("WWW-Authenticate"), `realm="s2s"`) {
		resp.Body.Close()

		fresh, err := client.Refresh(ctx, target)
		if err != nil {
			return 0, "", err
		}
		if resp, err = do(fresh); err != nil {
			return 0, "", err
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

// fetchWithFor is the same call with the transport doing the work.
func fetchWithFor(ctx context.Context, client *s2s.Client, target, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.For(target).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", k)
		os.Exit(1)
	}
	return v
}
