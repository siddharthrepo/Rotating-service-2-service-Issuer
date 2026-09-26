package rediscache

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

// Stats counts calls per grant, bucketed by minute.
type Stats struct{ c *redis.Client }

func NewStats(c *redis.Client) *Stats { return &Stats{c: c} }

func statKey(grantID uint64, minute int64) string {
	return fmt.Sprintf("%s%d:%d", constants.RedisKeyStats, grantID, minute)
}

// Record counts one validation.
func (s *Stats) Record(ctx context.Context, grantID uint64, allowed bool) {
	field := "calls"
	if !allowed {
		field = "denies"
	}
	key := statKey(grantID, time.Now().Unix()/60)

	pipe := s.c.Pipeline()
	pipe.HIncrBy(ctx, key, field, 1)

	pipe.Expire(ctx, key, constants.StatsBucketTTL)
	_, _ = pipe.Exec(ctx)
}

// Drain reads and removes every bucket older than the current minute.
func (s *Stats) Drain(ctx context.Context) ([]structs.GrantStatBucket, error) {
	current := time.Now().Unix() / 60
	out := []structs.GrantStatBucket{}

	var cursor uint64
	for {
		keys, next, err := s.c.Scan(ctx, cursor, constants.RedisKeyStats+"*", 500).Result()
		if err != nil {
			return nil, fmt.Errorf("scan stat keys: %w", err)
		}
		for _, key := range keys {
			grantID, minute, ok := parseStatKey(key)
			if !ok || minute >= current {
				continue
			}
			vals, err := s.c.HGetAll(ctx, key).Result()
			if err != nil {
				continue
			}
			out = append(out, structs.GrantStatBucket{
				GrantID:     grantID,
				BucketStart: time.Unix(minute*60, 0).UTC(),
				CallCount:   atoi64(vals["calls"]),
				DenyCount:   atoi64(vals["denies"]),
			})
			s.c.Del(ctx, key)
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return out, nil
}

func parseStatKey(key string) (grantID uint64, minute int64, ok bool) {
	rest := strings.TrimPrefix(key, constants.RedisKeyStats)
	parts := strings.Split(rest, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	g, err1 := strconv.ParseUint(parts[0], 10, 64)
	m, err2 := strconv.ParseInt(parts[1], 10, 64)
	return g, m, err1 == nil && err2 == nil
}

func atoi64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}
