// Package cache holds cache implementations.
package cache

import (
	"context"
	"time"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

// NoopCurrentTokens satisfies the current-token cache with permanent misses.
type NoopCurrentTokens struct{}

func NewNoopCurrentTokens() NoopCurrentTokens { return NoopCurrentTokens{} }

// Get always misses.
func (NoopCurrentTokens) Get(context.Context, uint64) (*structs.CurrentToken, error) {
	return nil, nil
}

func (NoopCurrentTokens) Set(context.Context, uint64, *structs.CurrentToken, time.Duration) error {
	return nil
}

func (NoopCurrentTokens) Delete(context.Context, uint64) error { return nil }

// NoopTokenCache satisfies the validation cache with permanent misses, so the
// service runs correctly with Redis disabled -- every introspect simply reads
// MySQL.
type NoopTokenCache struct{}

func NewNoopTokenCache() NoopTokenCache { return NoopTokenCache{} }

func (NoopTokenCache) Get(context.Context, string) (*structs.CachedToken, error) { return nil, nil }

func (NoopTokenCache) Set(context.Context, string, *structs.CachedToken, time.Duration) error {
	return nil
}

func (NoopTokenCache) SetIfAbsent(context.Context, string, *structs.CachedToken, time.Duration) (bool, error) {
	return true, nil
}

func (NoopTokenCache) Delete(context.Context, ...string) error { return nil }

// NoopRateLimiter allows everything.
type NoopRateLimiter struct{}

func NewNoopRateLimiter() NoopRateLimiter { return NoopRateLimiter{} }

func (NoopRateLimiter) Allow(context.Context, string, int, time.Time) (bool, error) {
	return true, nil
}

// NoopServiceAuth disables the client-credential result cache, so every request
// pays full argon2 cost.
type NoopServiceAuth struct{}

func NewNoopServiceAuth() NoopServiceAuth { return NoopServiceAuth{} }

func (NoopServiceAuth) Get(context.Context, string) (*structs.CachedAuth, error) { return nil, nil }

func (NoopServiceAuth) Set(context.Context, string, *structs.CachedAuth, time.Duration) error {
	return nil
}

func (NoopServiceAuth) Delete(context.Context, string) error { return nil }

// NoopStats discards graph telemetry.
type NoopStats struct{}

func NewNoopStats() NoopStats { return NoopStats{} }

func (NoopStats) Record(context.Context, uint64, bool) {}

func (NoopStats) Drain(context.Context) ([]structs.GrantStatBucket, error) { return nil, nil }
