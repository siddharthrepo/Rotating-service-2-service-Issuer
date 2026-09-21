package controller

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/controller/render"
	"github.com/siddharth120604/rotating-s2s/pkg/middleware"
	"github.com/siddharth120604/rotating-s2s/pkg/service"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type tokensService interface {
	Issue(ctx context.Context, in service.IssueInput) (*service.IssueResult, error)
	Introspect(ctx context.Context, asker *structs.Service, token string) (*structs.IntrospectResponse, error)
}

// Machine serves the two endpoints services themselves call.
type Machine struct{ tokens tokensService }

func NewMachine(tokens tokensService) *Machine { return &Machine{tokens: tokens} }

// IssueToken handles POST /v1/token.
func (m *Machine) IssueToken(c *gin.Context) {
	caller, ok := middleware.CallerFrom(c)
	if !ok {
		render.Error(c, apperr.InvalidClient)
		return
	}

	var req structs.IssueTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		render.Error(c, apperr.BadRequest.WithMessage("invalid request body: %v", err))
		return
	}

	result, err := m.tokens.Issue(c.Request.Context(), service.IssueInput{
		Caller:     caller,
		TargetName: req.Target,
		RemoteIP:   c.ClientIP(),
	})
	if err != nil {
		render.Error(c, err)
		return
	}

	if result.Minted {
		render.Created(c, result.Response)
		return
	}
	render.OK(c, result.Response)
}

// Introspect handles POST /v1/introspect.
func (m *Machine) Introspect(c *gin.Context) {
	asker, ok := middleware.CallerFrom(c)
	if !ok {
		render.Error(c, apperr.InvalidClient)
		return
	}

	var req structs.IntrospectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		render.Error(c, apperr.BadRequest.WithMessage("invalid request body: %v", err))
		return
	}

	resp, err := m.tokens.Introspect(c.Request.Context(), asker, req.Token)
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, resp)
}
