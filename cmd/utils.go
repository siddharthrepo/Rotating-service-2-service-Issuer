package cmd

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/siddharth120604/rotating-s2s/pkg/cache"
	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/repository/rediscache"
	"github.com/siddharth120604/rotating-s2s/pkg/service"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

func buildCache(cfg *structs.Config, log *zap.Logger) (
	service.CurrentTokens, service.TokenCache, service.RateLimiter, service.ServiceAuthCache,
	service.StatsRecorder, func(context.Context) error, func(), error,
) {
	if !cfg.Redis.Enabled {
		log.Warn("redis disabled: every validation reads MySQL and pays full argon2 cost",
			zap.String("hint", "set redis.enabled=true for the intended hot path"))
		return cache.NewNoopCurrentTokens(), cache.NewNoopTokenCache(),
			cache.NewNoopRateLimiter(), cache.NewNoopServiceAuth(), cache.NewNoopStats(),
			nil, func() {}, nil
	}

	client, err := rediscache.Open(cfg.Redis)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	log.Info("connected to redis", zap.String("addr", cfg.Redis.Addr))

	ping := func(ctx context.Context) error { return rediscache.Ping(ctx, client) }

	return rediscache.NewCurrentTokens(client),
		rediscache.NewTokenCache(client),
		rediscache.NewRateLimiter(client),
		rediscache.NewServiceAuth(client),
		rediscache.NewStats(client),
		ping,
		func() { _ = client.Close() },
		nil
}

func runStatsFlusher(ctx context.Context, graph *service.Graph, log *zap.Logger) {
	ticker := time.NewTicker(constants.StatsFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():

			flushOnce(context.Background(), graph, log)
			return
		case <-ticker.C:
			flushOnce(ctx, graph, log)
		}
	}
}

func flushOnce(ctx context.Context, graph *service.Graph, log *zap.Logger) {
	n, err := graph.Flush(ctx)
	if err != nil {
		log.Warn("flushing graph stats", zap.Error(err))
		return
	}
	if n > 0 {
		log.Debug("flushed graph stats", zap.Int("buckets", n))
	}
}
