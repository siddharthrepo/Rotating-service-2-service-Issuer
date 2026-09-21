package rediscache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Ping is used by the readiness probe.
func Ping(ctx context.Context, c *redis.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.Ping(ctx).Err()
}
