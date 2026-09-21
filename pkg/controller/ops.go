package controller

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

// Ops serves liveness and readiness.
type Ops struct {
	db    *sqlx.DB
	redis func(context.Context) error
}

func NewOps(db *sqlx.DB, redisPing func(context.Context) error) *Ops {
	return &Ops{db: db, redis: redisPing}
}

// Healthz is liveness: the process is up.
func (o *Ops) Healthz(c *gin.Context) {
	c.JSON(http.StatusOK, structs.HealthResponse{Status: "ok"})
}

// Readyz is readiness: this replica can serve traffic right now.
func (o *Ops) Readyz(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	checks := map[string]string{}
	status := http.StatusOK

	if err := o.db.PingContext(ctx); err != nil {
		checks["mysql"] = "error: " + err.Error()
		status = http.StatusServiceUnavailable
	} else {
		checks["mysql"] = "ok"
	}

	if o.redis != nil {
		if err := o.redis(ctx); err != nil {
			checks["redis"] = "degraded: " + err.Error()
		} else {
			checks["redis"] = "ok"
		}
	}

	body := structs.HealthResponse{Status: "ready", Checks: checks}
	if status != http.StatusOK {
		body.Status = "not ready"
	}
	c.JSON(status, body)
}
