package s2s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeIssuer struct {
	*httptest.Server
	issues      atomic.Int64
	introspects atomic.Int64

	mu       sync.Mutex
	token    string
	active   bool
	rotateIn int64
	down     bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{token: "s2s_first", active: true, rotateIn: 1}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		down, tok, rot := f.down, f.token, f.rotateIn
		f.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		f.issues.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			Token: tok, TokenType: "Bearer", Target: "billing",
			Scopes: []string{"billing:read"}, IssuedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour), ExpiresIn: 3600, RotateAfter: rot,
		})
	})
	mux.HandleFunc("/v1/introspect", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		down, tok, active := f.down, f.token, f.active
		f.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		f.introspects.Add(1)
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		if body.Token != tok || !active {
			_ = json.NewEncoder(w).Encode(Introspection{Active: false, Reason: "revoked"})
			return
		}
		_ = json.NewEncoder(w).Encode(Introspection{
			Active: true, Caller: "orders", Target: "billing",
			Scopes: []string{"billing:read"}, JTI: "01TEST",
		})
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIssuer) set(fn func(*fakeIssuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func testConfig(url string) Config {
	return Config{IssuerURL: url, ClientID: "cid", ClientSecret: "secret", Timeout: 2 * time.Second}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{}); err != ErrMissingConfig {
		t.Fatalf("expected ErrMissingConfig, got %v", err)
	}
}

// One token is fetched and reused; a second call must not hit the issuer.
func TestTokenIsReused(t *testing.T) {
	f := newFakeIssuer(t)
	c, err := New(testConfig(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for i := 0; i < 5; i++ {
		if _, err := c.Token(t.Context(), "billing"); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.issues.Load(); got != 1 {
		t.Fatalf("expected 1 issuance, got %d", got)
	}
}

// Concurrent callers on a cold target must collapse into ONE issuance.
func TestConcurrentFetchCollapses(t *testing.T) {
	f := newFakeIssuer(t)
	c, err := New(testConfig(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Token(t.Context(), "billing"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if got := f.issues.Load(); got != 1 {
		t.Fatalf("expected 1 issuance for 50 concurrent callers, got %d", got)
	}
}

// The transport must attach the token without mutating the caller's request.
func TestTransportInjectsAndDoesNotMutate(t *testing.T) {
	f := newFakeIssuer(t)
	c, err := New(testConfig(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var seen string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
	}))
	defer target.Close()

	req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	resp, err := c.For("billing").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if seen != "Bearer s2s_first" {
		t.Fatalf("expected injected token, got %q", seen)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("caller's request was mutated: %q", got)
	}
}

// A 401 carrying the s2s marker triggers exactly one refresh-and-retry.
func TestForceRotateRecovery(t *testing.T) {
	f := newFakeIssuer(t)
	c, err := New(testConfig(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var attempts atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {

			f.set(func(fi *fakeIssuer) { fi.token = "s2s_rotated" })
			w.Header().Set("WWW-Authenticate", `Bearer realm="s2s", error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s2s_rotated" {
			t.Errorf("retry carried stale token: %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	resp, err := c.For("billing").Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected recovery to 200, got %d", resp.StatusCode)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected exactly 2 attempts, got %d", got)
	}
}

// A 401 from the target's OWN logic must NOT cause a refresh.
func TestPlain401IsNotRetried(t *testing.T) {
	f := newFakeIssuer(t)
	c, err := New(testConfig(f.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var attempts atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "your app says no", http.StatusUnauthorized)
	}))
	defer target.Close()

	resp, err := c.For("billing").Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := attempts.Load(); got != 1 {
		t.Fatalf("a non-s2s 401 was retried: %d attempts", got)
	}
	if got := f.issues.Load(); got != 1 {
		t.Fatalf("a non-s2s 401 triggered a refresh: %d issuances", got)
	}
}

// Concurrent validations of one token collapse into ONE introspect call.
func TestValidatorCollapsesConcurrentChecks(t *testing.T) {
	f := newFakeIssuer(t)
	v, err := NewValidator(testConfig(f.URL))
	if err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	protected := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		caller, _ := CallerFrom(r.Context())
		fmt.Fprint(w, caller)
	}))
	srv := httptest.NewServer(protected)
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			req.Header.Set("Authorization", "Bearer s2s_first")
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := f.introspects.Load(); got > 5 {
		t.Fatalf("expected concurrent checks to collapse, got %d introspects", got)
	}
}

func TestMiddlewareRejects(t *testing.T) {
	f := newFakeIssuer(t)
	v, _ := NewValidator(testConfig(f.URL))
	srv := httptest.NewServer(v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()

	for _, tc := range []struct{ name, auth string }{
		{"no header", ""},
		{"wrong token", "Bearer s2s_nope"},
		{"not bearer", "Basic abc"},
	} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", tc.name, resp.StatusCode)
		}

		if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `realm="s2s"`) {
			t.Errorf("%s: missing s2s marker in WWW-Authenticate", tc.name)
		}
	}
}

// With the issuer down, a previously-seen token is served from the degraded window,
// but one never seen still fails closed.
func TestDegradedMode(t *testing.T) {
	f := newFakeIssuer(t)
	cfg := testConfig(f.URL)
	cfg.DegradedWindow = time.Minute
	v, _ := NewValidator(cfg)

	if _, err := v.Validate(t.Context(), "s2s_first"); err != nil {
		t.Fatal(err)
	}
	f.set(func(fi *fakeIssuer) { fi.down = true })

	res, err := v.Validate(t.Context(), "s2s_first")
	if err != nil || !res.Active {
		t.Fatalf("known token should survive an issuer outage: %v %+v", err, res)
	}
	if _, err := v.Validate(t.Context(), "s2s_never_seen"); err == nil {
		t.Fatal("an unseen token must fail closed during an outage")
	}
}

func TestRequireScope(t *testing.T) {
	f := newFakeIssuer(t)
	v, _ := NewValidator(testConfig(f.URL))
	ok := httptest.NewServer(v.RequireScope("billing:read")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	defer ok.Close()
	denied := httptest.NewServer(v.RequireScope("billing:write")(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	defer denied.Close()

	for _, tc := range []struct {
		url  string
		want int
	}{{ok.URL, http.StatusOK}, {denied.URL, http.StatusForbidden}} {
		req, _ := http.NewRequest(http.MethodGet, tc.url, nil)
		req.Header.Set("Authorization", "Bearer s2s_first")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: want %d got %d", tc.url, tc.want, resp.StatusCode)
		}
	}
}

// Jitter must never push a refresh PAST the nominal interval.
func TestJitterStaysWithinWindow(t *testing.T) {
	const d = 900 * time.Second
	low := time.Duration(float64(d) * 0.9)
	for i := 0; i < 1000; i++ {
		got := jitter(d, 0.1)
		if got > d || got < low {
			t.Fatalf("jitter %v outside [%v, %v]", got, low, d)
		}
	}
}
