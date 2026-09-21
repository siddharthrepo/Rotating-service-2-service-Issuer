// Package middleware holds cross-cutting HTTP concerns.
package middleware

import (
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/controller/render"
	"github.com/siddharth120604/rotating-s2s/pkg/crypto"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

// RequestID accepts an inbound id so a trace survives across services, and mints
// one otherwise.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(constants.HeaderRequestID)
		if id == "" {
			id = crypto.NewID()
		}
		c.Set(constants.ContextRequestID, id)
		c.Header(constants.HeaderRequestID, id)
		c.Next()
	}
}

// Recovery converts a panic into a 500 rather than a dropped connection, and logs
// the stack once.
func Recovery(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if p := recover(); p != nil {
				log.Error("panic recovered",
					zap.Any("panic", p),
					zap.String("path", c.Request.URL.Path),
					zap.String("request_id", RequestIDFrom(c)),
					zap.ByteString("stack", debug.Stack()),
				)
				render.Error(c, apperr.Internal)
				c.Abort()
			}
		}()
		c.Next()
	}
}

// Logger emits one structured line per request, using zap's typed fields so the hot
// path stays allocation-free.
func Logger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		fields := [...]zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", time.Since(start)),
			zap.String("request_id", RequestIDFrom(c)),
			zap.String("remote_ip", c.ClientIP()),
		}

		switch status := c.Writer.Status(); {
		case status >= 500:
			log.Error("request", fields[:]...)
		case status >= 400:
			log.Warn("request", fields[:]...)
		default:
			log.Info("request", fields[:]...)
		}
	}
}

// AdminAPIKey gates the admin surface.
func AdminAPIKey(key string) gin.HandlerFunc {
	return func(c *gin.Context) {
		presented, ok := bearerToken(c)
		if !ok || !secureEqual(presented, key) {
			render.Error(c, apperr.Unauthorized.WithMessage("admin credentials required"))
			c.Abort()
			return
		}
		c.Set(constants.ContextActor, structs.Actor{
			Type: constants.ActorUser,
			ID:   "admin-api-key",
		})
		c.Next()
	}
}

// NoStore keeps credential-bearing responses out of any intermediary cache.
func NoStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Next()
	}
}
