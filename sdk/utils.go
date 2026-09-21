package s2s

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"time"
)

type ctxKey int

const (
	ctxCaller ctxKey = iota
	ctxScopes
)

// CallerFrom returns the verified name of the service that made this request.
func CallerFrom(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxCaller).(string)
	return v, ok
}

// ScopesFrom returns the scopes granted to the caller for this service.
func ScopesFrom(ctx context.Context) ([]string, bool) {
	v, ok := ctx.Value(ctxScopes).([]string)
	return v, ok
}

// HasScope reports whether the caller holds a scope.
func HasScope(ctx context.Context, scope string) bool {
	scopes, ok := ScopesFrom(ctx)
	if !ok {
		return false
	}
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func jitter(d time.Duration, fraction float64) time.Duration {
	if d <= 0 {
		return time.Second
	}
	spread := float64(d) * fraction
	return time.Duration(float64(d) - spread*rand.Float64())
}

func backoff(failures int, interval time.Duration) time.Duration {
	d := time.Second << min(failures, 6)
	if cap := interval / 4; cap > 0 && d > cap {
		return cap
	}
	return d
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func decodeIssuerError(resp *http.Response) error {
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return &issuerError{
		Status: resp.StatusCode,
		Code:   body.Error.Code,
		Msg:    body.Error.Message,
	}
}
