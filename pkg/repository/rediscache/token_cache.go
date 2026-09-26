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

// TokenCache fronts the validation lookup.
type TokenCache struct{ c *redis.Client }

func NewTokenCache(c *redis.Client) *TokenCache { return &TokenCache{c: c} }

// Get returns (nil, nil) on a miss.
func (t *TokenCache) Get(ctx context.Context, hash string) (*structs.CachedToken, error) {
	raw, err := t.c.Get(ctx, cache.TokenKey(hash)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get token: %w", err)
	}

	var out structs.CachedToken
	if err := json.Unmarshal(raw, &out); err != nil {

		return nil, fmt.Errorf("unmarshal cached token: %w", err)
	}
	return &out, nil
}

// Set stores a record under its hash.
func (t *TokenCache) Set(ctx context.Context, hash string, v *structs.CachedToken, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}

	raw := []byte(`{"nf":true}`)
	if !v.NotFound {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			return fmt.Errorf("marshal cached token: %w", err)
		}
	}
	if err := t.c.Set(ctx, cache.TokenKey(hash), raw, ttl).Err(); err != nil {
		return fmt.Errorf("redis set token: %w", err)
	}
	return nil
}

// SetIfAbsent stores a record only when the key is unset, using Redis SET NX.
//
// This is what makes revocation race-free. The read path repopulates with
// SetIfAbsent while revocation writes its tombstone with an unconditional Set,
// so the revoker always wins whichever order they interleave in:
//
//	reader repopulates, then revoker writes  -> tombstone overwrites   (Set wins)
//	revoker writes, then reader repopulates  -> NX fails, tombstone stays
//
// With a plain Delete the first ordering leaves a revoked token cached and
// valid for the remainder of its TTL.
func (t *TokenCache) SetIfAbsent(ctx context.Context, hash string, v *structs.CachedToken, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, nil
	}
	raw := []byte(`{"nf":true}`)
	if !v.NotFound {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			return false, fmt.Errorf("marshal cached token: %w", err)
		}
	}
	set, err := t.c.SetNX(ctx, cache.TokenKey(hash), raw, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis setnx token: %w", err)
	}
	return set, nil
}

// Delete removes entries.
func (t *TokenCache) Delete(ctx context.Context, hashes ...string) error {
	if len(hashes) == 0 {
		return nil
	}
	keys := make([]string, 0, len(hashes))
	for _, h := range hashes {
		keys = append(keys, cache.TokenKey(h))
	}
	if err := t.c.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("redis del tokens: %w", err)
	}
	return nil
}
