package rediscache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/cache"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

// CurrentTokens holds the plaintext token currently being handed out for each
// grant.
type CurrentTokens struct{ c *redis.Client }

func NewCurrentTokens(c *redis.Client) *CurrentTokens { return &CurrentTokens{c: c} }

func (t *CurrentTokens) Get(ctx context.Context, grantID uint64) (*structs.CurrentToken, error) {
	raw, err := t.c.Get(ctx, cache.CurrentTokenKey(grantID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get current token: %w", err)
	}

	var out structs.CurrentToken
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal current token: %w", err)
	}
	return &out, nil
}

// Set caches the plaintext with TTL = rotate_after, so the key expires exactly when
// the caller is due to come back for a new token.
func (t *CurrentTokens) Set(ctx context.Context, grantID uint64, v *structs.CurrentToken, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal current token: %w", err)
	}
	if err := t.c.Set(ctx, cache.CurrentTokenKey(grantID), raw, ttl).Err(); err != nil {
		return fmt.Errorf("redis set current token: %w", err)
	}
	return nil
}

// Delete stops the grant's token being handed to new callers.
func (t *CurrentTokens) Delete(ctx context.Context, grantID uint64) error {
	if err := t.c.Del(ctx, cache.CurrentTokenKey(grantID)).Err(); err != nil {
		return fmt.Errorf("redis del current token: %w", err)
	}
	return nil
}
