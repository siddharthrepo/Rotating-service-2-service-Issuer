// Package apperr gives every layer one way to express a failure and the HTTP layer
// one way to render it.
package apperr

import (
	"fmt"
	"net/http"
)

type Error struct {
	Code    string
	Message string
	Status  int
	err     error
}

func (e *Error) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.err }

// Wrap attaches a cause for logging without changing what the caller sees.
func (e *Error) Wrap(err error) *Error {
	c := *e
	c.err = err
	return &c
}

// WithMessage overrides the default message, keeping code and status.
func (e *Error) WithMessage(format string, args ...any) *Error {
	c := *e
	c.Message = fmt.Sprintf(format, args...)
	return &c
}

// Is reports whether err is this kind of application error, by code.
func (e *Error) Is(err error) bool {
	other := from(err)
	return other != nil && other.Code == e.Code
}

var (
	Internal     = def(http.StatusInternalServerError, "internal_error", "internal error")
	NotFound     = def(http.StatusNotFound, "not_found", "resource not found")
	Conflict     = def(http.StatusConflict, "conflict", "resource already exists")
	BadRequest   = def(http.StatusBadRequest, "bad_request", "invalid request")
	Unauthorized = def(http.StatusUnauthorized, "unauthorized", "authentication required")
	Forbidden    = def(http.StatusForbidden, "forbidden", "not permitted")
	RateLimited  = def(http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")

	ServiceNotFound = def(http.StatusNotFound, "unknown_service", "service not registered")
	ServiceExists   = def(http.StatusConflict, "service_exists", "service name already registered")
	ServiceDisabled = def(http.StatusForbidden, "service_disabled", "service is disabled")
	GrantNotFound   = def(http.StatusNotFound, "unknown_grant", "grant not found")
	GrantExists     = def(http.StatusConflict, "grant_exists", "grant already exists for this pair")
	GrantRevoked    = def(http.StatusForbidden, "grant_revoked", "grant has been revoked")
	SelfGrant       = def(http.StatusBadRequest, "self_grant", "a service cannot be granted access to itself")
	InvalidRotation = def(http.StatusBadRequest, "invalid_rotation", "rotate_after must be less than lifetime")
	LifetimeTooLong = def(http.StatusBadRequest, "lifetime_too_long", "lifetime exceeds the configured maximum")

	RevokedButCacheUnconfirmed = def(http.StatusInternalServerError, "cache_unconfirmed",
		"revoked in the database, but cache invalidation could not be confirmed; "+
			"the token may still be accepted until its cache entry expires")

	InvalidClient = def(http.StatusUnauthorized, "invalid_client", "invalid client credentials")
	NoGrant       = def(http.StatusForbidden, "no_grant", "no active grant from caller to target")
)
