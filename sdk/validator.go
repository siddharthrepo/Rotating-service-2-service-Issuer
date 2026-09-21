package s2s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Introspection is the issuer's verdict on a presented token.
type Introspection struct {
	Active    bool      `json:"active"`
	Reason    string    `json:"reason,omitempty"`
	Caller    string    `json:"caller,omitempty"`
	Target    string    `json:"target,omitempty"`
	Scopes    []string  `json:"scopes,omitempty"`
	JTI       string    `json:"jti,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Validator is the target half: it decides whether an inbound request carries a
// valid token for THIS service.
type Validator struct {
	cfg  Config
	http *http.Client

	checks singleflight.Group

	mu     sync.RWMutex
	recent map[string]cachedVerdict
}

type cachedVerdict struct {
	result *Introspection
	at     time.Time
}

func NewValidator(cfg Config) (*Validator, error) {
	if err := cfg.normalise(); err != nil {
		return nil, err
	}
	return &Validator{
		cfg:    cfg,
		http:   &http.Client{Transport: cfg.Transport, Timeout: cfg.Timeout},
		recent: make(map[string]cachedVerdict),
	}, nil
}

// Validate asks the issuer about a token.
func (v *Validator) Validate(ctx context.Context, token string) (*Introspection, error) {
	if token == "" {
		return &Introspection{Active: false, Reason: "not_found"}, nil
	}

	if cached := v.fromCache(token); cached != nil {
		return cached, nil
	}

	res, err, _ := v.checks.Do(token, func() (any, error) {
		return v.introspect(ctx, token)
	})
	if err != nil {

		if stale := v.fromDegraded(token); stale != nil {
			v.cfg.report(fmt.Errorf("s2s: issuer unreachable, serving degraded verdict: %w", err))
			return stale, nil
		}
		return nil, err
	}

	out := res.(*Introspection)
	v.remember(token, out)
	return out, nil
}

// Middleware rejects any request without a valid token for this service, and puts
// the verified caller identity into the request context.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			v.deny(w, "invalid_request", "a bearer token is required")
			return
		}

		res, err := v.Validate(r.Context(), token)
		if err != nil {

			v.cfg.report(err)
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		if !res.Active {
			v.deny(w, "invalid_token", res.Reason)
			return
		}

		ctx := context.WithValue(r.Context(), ctxCaller, res.Caller)
		ctx = context.WithValue(ctx, ctxScopes, res.Scopes)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScope is Middleware plus a scope check, for per-route authorisation.
func (v *Validator) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasScope(r.Context(), scope) {
				caller, _ := CallerFrom(r.Context())
				v.cfg.report(fmt.Errorf("s2s: %q lacks scope %q", caller, scope))
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer realm="s2s", error="insufficient_scope", scope=%q`, scope))
				http.Error(w, "insufficient scope", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

func (v *Validator) deny(w http.ResponseWriter, code, reason string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer realm="s2s", error=%q, error_description=%q`, code, reason))
	http.Error(w, "unauthorized: "+reason, http.StatusUnauthorized)
}

func (v *Validator) introspect(ctx context.Context, token string) (*Introspection, error) {
	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		v.cfg.IssuerURL+"/v1/introspect", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(v.cfg.ClientID, v.cfg.ClientSecret)

	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIssuer, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, decodeIssuerError(resp)
	}

	var out Introspection
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: decoding introspection: %v", ErrIssuer, err)
	}
	return &out, nil
}

func (v *Validator) fromCache(token string) *Introspection {
	if v.cfg.ValidationCacheTTL <= 0 {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.recent[token]
	if !ok || time.Since(e.at) > v.cfg.ValidationCacheTTL {
		return nil
	}
	return e.result
}

func (v *Validator) fromDegraded(token string) *Introspection {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.recent[token]
	if !ok || time.Since(e.at) > v.cfg.DegradedWindow {
		return nil
	}
	return e.result
}

func (v *Validator) remember(token string, res *Introspection) {
	if !res.Active {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.recent) > 10000 {
		v.recent = make(map[string]cachedVerdict)
	}
	v.recent[token] = cachedVerdict{result: res, at: time.Now()}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
