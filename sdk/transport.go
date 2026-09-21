package s2s

import (
	"net/http"
	"strings"
)

type transport struct {
	base   http.RoundTripper
	target string
	client *Client
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.client.token(req.Context(), t.target)
	if err != nil {
		return nil, err
	}

	first := req.Clone(req.Context())
	first.Header.Set("Authorization", "Bearer "+tok)

	resp, err := t.base.RoundTrip(first)
	if err != nil {
		return nil, err
	}

	if !t.shouldRetry(req, resp) {
		return resp, nil
	}

	fresh, ferr := t.client.forceRefresh(req.Context(), t.target)
	if ferr != nil {
		t.client.cfg.report(ferr)
		return resp, nil
	}

	resp.Body.Close()

	retry := req.Clone(req.Context())
	retry.Header.Set("Authorization", "Bearer "+fresh)
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		retry.Body = body
	}
	return t.base.RoundTrip(retry)
}

func (t *transport) shouldRetry(req *http.Request, resp *http.Response) bool {
	if resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	if !isS2SAuthFailure(resp) {
		return false
	}

	return req.Body == nil || req.GetBody != nil
}

func isS2SAuthFailure(resp *http.Response) bool {
	h := resp.Header.Get("WWW-Authenticate")
	return strings.Contains(h, `error="invalid_token"`) ||
		strings.Contains(h, `realm="s2s"`)
}
