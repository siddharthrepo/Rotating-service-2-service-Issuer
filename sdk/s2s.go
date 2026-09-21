// Package s2s is the client library for the rotating service-to-service token
// issuer.
package s2s

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config is shared by both halves.
type Config struct {
	IssuerURL string

	ClientID     string
	ClientSecret string

	Timeout time.Duration

	RefreshJitter float64

	ValidationCacheTTL time.Duration

	DegradedWindow time.Duration

	Transport http.RoundTripper

	OnError func(err error)
}

var (
	ErrNoToken       = errors.New("s2s: no usable token")
	ErrIssuer        = errors.New("s2s: issuer request failed")
	ErrUnauthorized  = errors.New("s2s: token rejected")
	ErrClosed        = errors.New("s2s: client closed")
	ErrMissingConfig = errors.New("s2s: IssuerURL, ClientID and ClientSecret are required")
)

func (c *Config) normalise() error {
	if c.IssuerURL == "" || c.ClientID == "" || c.ClientSecret == "" {
		return ErrMissingConfig
	}
	c.IssuerURL = strings.TrimRight(c.IssuerURL, "/")
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.RefreshJitter <= 0 {
		c.RefreshJitter = 0.1
	}
	if c.DegradedWindow <= 0 {
		c.DegradedWindow = 30 * time.Second
	}
	if c.Transport == nil {
		c.Transport = http.DefaultTransport
	}
	return nil
}

func (c *Config) report(err error) {
	if c.OnError != nil && err != nil {
		c.OnError(err)
	}
}

type issuerError struct {
	Status int
	Code   string
	Msg    string
}

func (e *issuerError) Error() string {
	return fmt.Sprintf("s2s: issuer returned %d (%s): %s", e.Status, e.Code, e.Msg)
}

func (e *issuerError) Unwrap() error { return ErrIssuer }
