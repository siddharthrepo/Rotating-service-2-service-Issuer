package rediscache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

// ServiceAuth memoises successful client-credential verifications.
type ServiceAuth struct{ c *redis.Client }

func NewServiceAuth(c *redis.Client) *ServiceAuth { return &ServiceAuth{c: c} }

func key(clientID string) string { return constants.RedisKeyService + clientID }

func (s *ServiceAuth) Get(ctx context.Context, clientID string) (*structs.CachedAuth, error) {
	raw, err := s.c.Get(ctx, key(clientID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get service auth: %w", err)
	}
	var out structs.CachedAuth
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal service auth: %w", err)
	}
	return &out, nil
}

func (s *ServiceAuth) Set(ctx context.Context, clientID string, v *structs.CachedAuth, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal service auth: %w", err)
	}
	if err := s.c.Set(ctx, key(clientID), raw, ttl).Err(); err != nil {
		return fmt.Errorf("redis set service auth: %w", err)
	}
	return nil
}

// Delete forces the next request to re-verify with argon2.
func (s *ServiceAuth) Delete(ctx context.Context, clientID string) error {
	if err := s.c.Del(ctx, key(clientID)).Err(); err != nil {
		return fmt.Errorf("redis del service auth: %w", err)
	}
	return nil
}
