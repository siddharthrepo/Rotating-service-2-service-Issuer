// Package controller translates HTTP to service calls and back.
package controller

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/controller/render"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/middleware"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type registryService interface {
	Create(ctx context.Context, in structs.CreateServiceInput) (*structs.Credentials, error)
	ByID(ctx context.Context, id uint64) (*structs.Service, error)
	List(ctx context.Context, f structs.ServiceFilter) ([]structs.Service, error)
	SetStatus(ctx context.Context, id uint64, status constants.ServiceStatus, actor structs.Actor) error
	RotateSecret(ctx context.Context, id uint64, actor structs.Actor) (*structs.Credentials, error)
}

type grantsService interface {
	Create(ctx context.Context, in structs.CreateGrantInput) (*structs.GrantDetail, error)
	ByID(ctx context.Context, id uint64) (*structs.GrantDetail, error)
	List(ctx context.Context, f structs.GrantFilter) ([]structs.GrantDetail, error)
	UpdatePolicy(ctx context.Context, in structs.UpdateGrantInput) (*structs.GrantDetail, error)
}

type revocationService interface {
	RevokeGrant(ctx context.Context, grantID uint64, actor structs.Actor, reason string) (*structs.RevokeResponse, error)
	ForceRotate(ctx context.Context, grantID uint64, actor structs.Actor, reason string) (*structs.RotateResponse, error)
}

type auditService interface {
	List(ctx context.Context, f structs.AuditFilter) ([]structs.AuditEntry, error)
}

type authenticator interface {
	Authenticate(ctx context.Context, clientID, secret string) (*structs.Service, error)
}

type Admin struct {
	registry registryService
	grants   grantsService
	revoke   revocationService
	audit    auditService
}

func NewAdmin(registry registryService, grants grantsService, revoke revocationService, audit auditService) *Admin {
	return &Admin{registry: registry, grants: grants, revoke: revoke, audit: audit}
}

// CreateService registers an identity and returns its credentials once.
func (a *Admin) CreateService(c *gin.Context) {
	var req structs.CreateServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		render.Error(c, apperr.BadRequest.WithMessage("invalid request body: %v", err))
		return
	}

	creds, err := a.registry.Create(c.Request.Context(), structs.CreateServiceInput{
		Name:        req.Name,
		OwnerTeam:   req.OwnerTeam,
		Description: req.Description,
		Actor:       middleware.ActorFrom(c),
		RemoteIP:    c.ClientIP(),
	})
	if err != nil {
		render.Error(c, err)
		return
	}
	render.Created(c, toCredentialsResponse(creds))
}

func (a *Admin) ListServices(c *gin.Context) {
	items, err := a.registry.List(c.Request.Context(), structs.ServiceFilter{
		OwnerTeam: c.Query("owner_team"),
		Status:    c.Query("status"),
		Limit:     queryInt(c, "limit", constants.DefaultPageLimit),
		Offset:    queryInt(c, "offset", 0),
	})
	if err != nil {
		render.Error(c, err)
		return
	}

	out := make([]structs.ServiceResponse, 0, len(items))
	for i := range items {
		out = append(out, toServiceResponse(&items[i]))
	}
	render.List(c, out, len(out))
}

func (a *Admin) GetService(c *gin.Context) {
	id, err := pathUint(c, "id")
	if err != nil {
		render.Error(c, err)
		return
	}
	svc, err := a.registry.ByID(c.Request.Context(), id)
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, toServiceResponse(svc))
}

func (a *Admin) UpdateServiceStatus(c *gin.Context) {
	id, err := pathUint(c, "id")
	if err != nil {
		render.Error(c, err)
		return
	}
	var req structs.UpdateServiceStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		render.Error(c, apperr.BadRequest.WithMessage("invalid request body: %v", err))
		return
	}

	if err := a.registry.SetStatus(c.Request.Context(), id,
		constants.ServiceStatus(req.Status), middleware.ActorFrom(c)); err != nil {
		render.Error(c, err)
		return
	}

	svc, err := a.registry.ByID(c.Request.Context(), id)
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, toServiceResponse(svc))
}

// RotateServiceSecret issues a new bootstrap credential.
func (a *Admin) RotateServiceSecret(c *gin.Context) {
	id, err := pathUint(c, "id")
	if err != nil {
		render.Error(c, err)
		return
	}
	creds, err := a.registry.RotateSecret(c.Request.Context(), id, middleware.ActorFrom(c))
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, toCredentialsResponse(creds))
}

func (a *Admin) CreateGrant(c *gin.Context) {
	var req structs.CreateGrantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		render.Error(c, apperr.BadRequest.WithMessage("invalid request body: %v", err))
		return
	}

	lifetime, err := parseDuration(req.Lifetime, "lifetime")
	if err != nil {
		render.Error(c, err)
		return
	}
	rotateAfter, err := parseDuration(req.RotateAfter, "rotate_after")
	if err != nil {
		render.Error(c, err)
		return
	}

	grant, err := a.grants.Create(c.Request.Context(), structs.CreateGrantInput{
		CallerName:  req.Caller,
		TargetName:  req.Target,
		Scopes:      req.Scopes,
		Lifetime:    lifetime,
		RotateAfter: rotateAfter,
		Actor:       middleware.ActorFrom(c),
		RemoteIP:    c.ClientIP(),
	})
	if err != nil {
		render.Error(c, err)
		return
	}
	render.Created(c, toGrantResponse(grant))
}

func (a *Admin) ListGrants(c *gin.Context) {
	items, err := a.grants.List(c.Request.Context(), structs.GrantFilter{
		CallerID: uint64(queryInt(c, "caller_id", 0)),
		TargetID: uint64(queryInt(c, "target_id", 0)),
		Status:   c.Query("status"),
		Limit:    queryInt(c, "limit", constants.DefaultPageLimit),
		Offset:   queryInt(c, "offset", 0),
	})
	if err != nil {
		render.Error(c, err)
		return
	}

	out := make([]structs.GrantResponse, 0, len(items))
	for i := range items {
		out = append(out, toGrantResponse(&items[i]))
	}
	render.List(c, out, len(out))
}

func (a *Admin) GetGrant(c *gin.Context) {
	id, err := pathUint(c, "id")
	if err != nil {
		render.Error(c, err)
		return
	}
	grant, err := a.grants.ByID(c.Request.Context(), id)
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, toGrantResponse(grant))
}

func (a *Admin) UpdateGrant(c *gin.Context) {
	id, err := pathUint(c, "id")
	if err != nil {
		render.Error(c, err)
		return
	}
	var req structs.UpdateGrantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		render.Error(c, apperr.BadRequest.WithMessage("invalid request body: %v", err))
		return
	}

	lifetime, err := parseDuration(req.Lifetime, "lifetime")
	if err != nil {
		render.Error(c, err)
		return
	}
	rotateAfter, err := parseDuration(req.RotateAfter, "rotate_after")
	if err != nil {
		render.Error(c, err)
		return
	}

	grant, err := a.grants.UpdatePolicy(c.Request.Context(), structs.UpdateGrantInput{
		ID:          id,
		Scopes:      req.Scopes,
		Lifetime:    lifetime,
		RotateAfter: rotateAfter,
		Actor:       middleware.ActorFrom(c),
	})
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, toGrantResponse(grant))
}

// RevokeGrant kills every live token AND blocks further issuance.
func (a *Admin) RevokeGrant(c *gin.Context) {
	id, reason, ok := a.revocationArgs(c)
	if !ok {
		return
	}
	resp, err := a.revoke.RevokeGrant(c.Request.Context(), id, middleware.ActorFrom(c), reason)
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, resp)
}

// RotateGrant kills every live token and mints a replacement.
func (a *Admin) RotateGrant(c *gin.Context) {
	id, reason, ok := a.revocationArgs(c)
	if !ok {
		return
	}
	resp, err := a.revoke.ForceRotate(c.Request.Context(), id, middleware.ActorFrom(c), reason)
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, resp)
}

func (a *Admin) ListAudit(c *gin.Context) {
	items, err := a.audit.List(c.Request.Context(), structs.AuditFilter{
		ActorID:    c.Query("actor_id"),
		Action:     c.Query("action"),
		TargetType: c.Query("target_type"),
		TargetID:   c.Query("target_id"),
		Limit:      queryInt(c, "limit", constants.DefaultPageLimit),
		Offset:     queryInt(c, "offset", 0),
	})
	if err != nil {
		render.Error(c, err)
		return
	}

	out := make([]structs.AuditResponse, 0, len(items))
	for i := range items {
		out = append(out, toAuditResponse(&items[i]))
	}
	render.List(c, out, len(out))
}
