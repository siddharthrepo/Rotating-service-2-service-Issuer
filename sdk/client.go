package s2s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Client is the caller half: it obtains and keeps fresh a token for each target
// this service calls.
type Client struct {
	cfg  Config
	http *http.Client

	mu      sync.RWMutex
	targets map[string]*targetState

	refreshes singleflight.Group
	done      chan struct{}
	closeOnce sync.Once
}

type targetState struct {
	name string

	mu          sync.RWMutex
	token       string
	expiresAt   time.Time
	rotateAfter time.Duration

	started sync.Once
}

func New(cfg Config) (*Client, error) {
	if err := cfg.normalise(); err != nil {
		return nil, err
	}
	return &Client{
		cfg:     cfg,
		http:    &http.Client{Transport: cfg.Transport, Timeout: cfg.Timeout},
		targets: make(map[string]*targetState),
		done:    make(chan struct{}),
	}, nil
}

// For returns an *http.Client that attaches a valid token for target on every
// request, refreshing transparently.
func (c *Client) For(target string) *http.Client {
	return &http.Client{
		Transport: &transport{base: c.cfg.Transport, target: target, client: c},
		Timeout:   0,
	}
}

// Token exposes the current token for callers not using the HTTP client -- gRPC
// metadata, message headers, and similar. It returns the cached token when one
// is valid, fetching only when there is none.
func (c *Client) Token(ctx context.Context, target string) (string, error) {
	return c.token(ctx, target)
}

// Refresh discards the cached token and fetches a new one.
//
// Callers using For() never need this -- its transport handles force-rotate
// recovery itself. It exists for Token() users, who must recognise a rejected
// token and replace it by hand.
func (c *Client) Refresh(ctx context.Context, target string) (string, error) {
	return c.forceRefresh(ctx, target)
}

// Close stops all background refreshers.
func (c *Client) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *Client) token(ctx context.Context, target string) (string, error) {
	t := c.targetState(target)

	t.mu.RLock()
	tok, exp := t.token, t.expiresAt
	t.mu.RUnlock()
	if tok != "" && time.Now().Before(exp) {
		return tok, nil
	}
	return c.refresh(ctx, target)
}

func (c *Client) refresh(ctx context.Context, target string) (string, error) {
	select {
	case <-c.done:
		return "", ErrClosed
	default:
	}

	v, err, _ := c.refreshes.Do(target, func() (any, error) {
		resp, err := c.issue(ctx, target)
		if err != nil {
			return nil, err
		}

		t := c.targetState(target)
		t.mu.Lock()
		t.token = resp.Token
		t.expiresAt = resp.ExpiresAt
		t.rotateAfter = time.Duration(resp.RotateAfter) * time.Second
		t.mu.Unlock()

		t.started.Do(func() { go c.runRefresher(t) })

		return resp.Token, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (c *Client) forceRefresh(ctx context.Context, target string) (string, error) {
	t := c.targetState(target)
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
	return c.refresh(ctx, target)
}

func (c *Client) runRefresher(t *targetState) {
	failures := 0
	for {
		t.mu.RLock()
		interval := t.rotateAfter
		t.mu.RUnlock()

		wait := jitter(interval, c.cfg.RefreshJitter)
		if failures > 0 {

			wait = backoff(failures, interval)
		}

		select {
		case <-c.done:
			return
		case <-time.After(wait):
		}

		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
		_, err := c.refresh(ctx, t.name)
		cancel()

		if err != nil {
			failures++
			c.cfg.report(fmt.Errorf("s2s: refresh for %q failed (attempt %d): %w", t.name, failures, err))
			continue
		}
		failures = 0
	}
}

func (c *Client) targetState(target string) *targetState {
	c.mu.RLock()
	t, ok := c.targets[target]
	c.mu.RUnlock()
	if ok {
		return t
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.targets[target]; ok {
		return t
	}
	t = &targetState{name: target}
	c.targets[target] = t
	return t
}

type tokenResponse struct {
	Token       string    `json:"token"`
	TokenType   string    `json:"token_type"`
	Target      string    `json:"target"`
	Scopes      []string  `json:"scopes"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ExpiresIn   int64     `json:"expires_in"`
	RotateAfter int64     `json:"rotate_after"`
}

func (c *Client) issue(ctx context.Context, target string) (*tokenResponse, error) {
	body, err := json.Marshal(map[string]string{"target": target})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.IssuerURL+"/v1/token", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIssuer, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, decodeIssuerError(resp)
	}

	var out tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: decoding token response: %v", ErrIssuer, err)
	}
	if out.Token == "" {
		return nil, ErrNoToken
	}
	return &out, nil
}
