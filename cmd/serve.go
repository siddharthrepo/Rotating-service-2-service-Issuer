package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/siddharth120604/rotating-s2s/pkg/config"
	"github.com/siddharth120604/rotating-s2s/pkg/controller"
	"github.com/siddharth120604/rotating-s2s/pkg/repository/mysql"
	"github.com/siddharth120604/rotating-s2s/pkg/service"
	"github.com/siddharth120604/rotating-s2s/pkg/telemetry"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the HTTP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		log, err := telemetry.NewLogger(cfg.Log)
		if err != nil {
			return err
		}
		defer telemetry.Sync(log)

		db, err := mysql.Open(cfg.MySQL)
		if err != nil {
			return err
		}
		defer db.Close()
		log.Info("connected to mysql")

		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		// Wiring is explicit and top-down: repositories, then services, then
		// the HTTP layer. Each layer receives the one below as an interface.
		var (
			serviceRepo = mysql.NewServiceRepo(db)
			grantRepo   = mysql.NewGrantRepo(db)
			auditRepo   = mysql.NewAuditRepo(db)
			tokenRepo   = mysql.NewTokenRepo(db)
			userRepo    = mysql.NewUserRepo(db)
			graphRepo   = mysql.NewGraphRepo(db)
			txManager   = mysql.NewTxManager(db)

			auditSvc = service.NewAudit(auditRepo)
		)

		currentTokens, tokenCache, limiter, authCache, stats, redisPing, closeCache, err := buildCache(cfg, log)
		if err != nil {
			return err
		}
		defer closeCache()

		registrySvc := service.NewRegistry(serviceRepo, auditSvc, cfg.Security.Argon2,
			authCache, cfg.Cache.ServiceTTL)
		grantsSvc := service.NewGrants(grantRepo, registrySvc, auditSvc, cfg.Tokens)

		tokensSvc := service.NewTokens(tokenRepo, grantsSvc, currentTokens, tokenCache,
			txManager, auditSvc, stats, cfg.Cache.NegativeTTL)
		revocationSvc := service.NewRevocation(tokenRepo, grantRepo, currentTokens,
			tokenCache, txManager, auditSvc, log)
		authSvc := service.NewAuth(userRepo, auditSvc, cfg.Security.Argon2)
		graphSvc := service.NewGraph(graphRepo, stats)

		go runStatsFlusher(ctx, graphSvc, log)

		deps := controller.Deps{
			Config:        cfg,
			Log:           log,
			DB:            db,
			RedisPing:     redisPing,
			Registry:      registrySvc,
			Grants:        grantsSvc,
			Audit:         auditSvc,
			Revoke:        revocationSvc,
			Auth:          authSvc,
			GraphSvc:      graphSvc,
			Tokens:        tokensSvc,
			Authenticator: registrySvc,
			Limiter:       limiter,
		}

		api := &http.Server{
			Addr:         cfg.Server.Addr,
			Handler:      controller.NewRouter(deps),
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
		}
		ops := &http.Server{
			Addr:         cfg.Server.OpsAddr,
			Handler:      controller.NewOpsRouter(deps),
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
		}

		errCh := make(chan error, 2)
		go listen(api, "api", cfg.Server.Addr, log, errCh)
		go listen(ops, "ops", cfg.Server.OpsAddr, log, errCh)

		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			log.Info("shutdown signal received", zap.Duration("grace", cfg.Server.ShutdownGrace))
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownGrace)
		defer cancel()

		if err := api.Shutdown(shutdownCtx); err != nil {
			log.Error("api shutdown", zap.Error(err))
		}
		if err := ops.Shutdown(shutdownCtx); err != nil {
			log.Error("ops shutdown", zap.Error(err))
		}
		log.Info("stopped cleanly")
		return nil
	},
}

func listen(srv *http.Server, name, addr string, log *zap.Logger, errCh chan<- error) {
	log.Info("listening", zap.String("server", name), zap.String("addr", addr))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- fmt.Errorf("%s server: %w", name, err)
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
