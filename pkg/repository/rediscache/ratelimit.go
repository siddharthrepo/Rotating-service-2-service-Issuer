package rediscache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter is a fixed-window counter per client per minute.
type RateLimiter struct{ c *redis.Client }

func NewRateLimiter(c *redis.Client) *RateLimiter { return &RateLimiter{c: c} }

// Allow reports whether this request fits under the limit.
func (r *RateLimiter) Allow(ctx context.Context, key string, limit int, now time.Time) (bool, error) {
	if limit <= 0 {
		return true, nil
	}

	windowKey := fmt.Sprintf("rl:%s:%d", key, now.Unix()/60)

	pipe := r.c.TxPipeline()
	count := pipe.Incr(ctx, windowKey)

	pipe.Expire(ctx, windowKey, 2*time.Minute)
	if _, err := pipe.Exec(ctx); err != nil {
		return true, fmt.Errorf("rate limit check: %w", err)
	}
	return count.Val() <= int64(limit), nil
}
