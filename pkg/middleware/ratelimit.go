package middleware

import (
	"context"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/controller/render"
)

type rateLimiter interface {
	Allow(ctx context.Context, key string, limit int, now time.Time) (bool, error)
}

// RateLimit caps requests per authenticated client per minute.
func RateLimit(limiter rateLimiter, limit int, bucket string) gin.HandlerFunc {
	return func(c *gin.Context) {
		caller, ok := CallerFrom(c)
		if !ok {
			c.Next()
			return
		}

		allowed, err := limiter.Allow(c.Request.Context(), bucket+":"+caller.ClientID, limit, time.Now())
		if err != nil {

			c.Next()
			return
		}
		if !allowed {
			c.Header("Retry-After", strconv.Itoa(60-time.Now().Second()))
			render.Error(c, apperr.RateLimited.WithMessage(
				"rate limit of %d/min exceeded for %s", limit, caller.Name))
			c.Abort()
			return
		}
		c.Next()
	}
}
