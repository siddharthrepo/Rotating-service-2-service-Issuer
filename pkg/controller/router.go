package controller

import (
	"context"
	"io/fs"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	"github.com/siddharth120604/rotating-s2s/pkg/middleware"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
	"github.com/siddharth120604/rotating-s2s/web"
)

type rateLimiter interface {
	Allow(ctx context.Context, key string, limit int, now time.Time) (bool, error)
}

type Deps struct {
	Config *structs.Config
	Log    *zap.Logger
	DB     *sqlx.DB

	RedisPing func(context.Context) error

	Registry registryService
	Grants   grantsService
	Audit    auditService
	Revoke   revocationService
	Auth     authService
	GraphSvc graphService
	Tokens   tokensService

	Authenticator authenticator

	Limiter rateLimiter
}

// NewRouter builds the public API.
func NewRouter(d Deps) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(
		middleware.RequestID(),
		middleware.Recovery(d.Log),
		middleware.Logger(d.Log),
	)

	if d.Auth != nil {
		mountDashboard(r, d)
	}

	machine := NewMachine(d.Tokens)
	m := r.Group("/v1")
	m.Use(
		middleware.ClientCredentials(d.Authenticator),
		middleware.NoStore(),
	)
	{

		m.POST("/token", middleware.RateLimit(d.Limiter,
			d.Config.RateLimit.IssuancePerMinute, "tok"), machine.IssueToken)
		m.POST("/introspect", middleware.RateLimit(d.Limiter,
			d.Config.RateLimit.IntrospectPerMinute, "intro"), machine.Introspect)
	}

	admin := NewAdmin(d.Registry, d.Grants, d.Revoke, d.Audit)
	v1 := r.Group("/v1")
	v1.Use(
		middleware.AdminAPIKey(d.Config.Server.AdminAPIKey),
		middleware.NoStore(),
	)
	{
		v1.POST("/services", admin.CreateService)
		v1.GET("/services", admin.ListServices)
		v1.GET("/services/:id", admin.GetService)
		v1.PATCH("/services/:id", admin.UpdateServiceStatus)
		v1.POST("/services/:id/rotate-secret", admin.RotateServiceSecret)

		v1.POST("/grants", admin.CreateGrant)
		v1.GET("/grants", admin.ListGrants)
		v1.GET("/grants/:id", admin.GetGrant)
		v1.PATCH("/grants/:id", admin.UpdateGrant)
		v1.POST("/grants/:id/revoke", admin.RevokeGrant)
		v1.POST("/grants/:id/rotate", admin.RotateGrant)

		v1.GET("/audit", admin.ListAudit)
	}

	return r
}

func mountDashboard(r *gin.Engine, d Deps) {
	dash, err := NewDashboard(d.Auth, d.GraphSvc, d.Registry, d.Grants,
		d.Revoke, d.Audit, d.Config.Server.SecureCookies)
	if err != nil {
		d.Log.Fatal("building dashboard templates", zap.Error(err))
	}

	static, err := fs.Sub(web.Static, "static")
	if err != nil {
		d.Log.Fatal("mounting static assets", zap.Error(err))
	}
	r.StaticFS("/static", http.FS(static))

	r.GET("/login", dash.LoginPage)
	r.POST("/login", dash.Login)

	ui := r.Group("/")
	ui.Use(middleware.Session(d.Auth, true))
	{
		ui.POST("/logout", dash.Logout)
		ui.GET("/", dash.GraphPage)
		ui.GET("/services", dash.ServicesPage)
		ui.GET("/grants", dash.GrantsPage)
		ui.GET("/audit", dash.AuditPage)
		ui.GET("/api/graph", dash.GraphData)

		act := ui.Group("/grants/:id")
		act.Use(middleware.RequireMutate())
		{
			act.POST("/revoke", dash.RevokeGrant)
			act.POST("/rotate", dash.RotateGrant)
		}
	}
}

// NewOpsRouter serves health on its own port, unauthenticated but not exposed
// alongside the API.
func NewOpsRouter(d Deps) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(middleware.Recovery(d.Log))

	ops := NewOps(d.DB, d.RedisPing)
	r.GET("/healthz", ops.Healthz)
	r.GET("/readyz", ops.Readyz)

	return r
}
