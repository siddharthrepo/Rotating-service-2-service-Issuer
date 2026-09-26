package service

import (
	"context"
	"strconv"

	"github.com/jmoiron/sqlx"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type grantRepo interface {
	Create(ctx context.Context, g *structs.Grant) error
	ByID(ctx context.Context, id uint64) (*structs.GrantDetail, error)
	ByPair(ctx context.Context, callerID, targetID uint64) (*structs.Grant, error)
	List(ctx context.Context, f structs.GrantFilter) ([]structs.GrantDetail, error)
	UpdatePolicy(ctx context.Context, g *structs.Grant) error
	SetRevoked(ctx context.Context, tx *sqlx.Tx, id uint64, reason string) error
}

// Grants owns the ACL: which service may call which, with what scopes, and on what
// rotation schedule.
type Grants struct {
	repo     grantRepo
	registry *Registry
	audit    *Audit
	policy   structs.Tokens
}

func NewGrants(repo grantRepo, registry *Registry, audit *Audit, policy structs.Tokens) *Grants {
	return &Grants{repo: repo, registry: registry, audit: audit, policy: policy}
}

func (g *Grants) Create(ctx context.Context, in structs.CreateGrantInput) (*structs.GrantDetail, error) {
	caller, err := g.registry.ByName(ctx, in.CallerName)
	if err != nil {
		return nil, err
	}
	target, err := g.registry.ByName(ctx, in.TargetName)
	if err != nil {
		return nil, err
	}
	if caller.ID == target.ID {
		return nil, apperr.SelfGrant
	}

	lifetime, rotateAfter, err := resolveTiming(g.policy, in.Lifetime, in.RotateAfter)
	if err != nil {
		return nil, err
	}

	grant := &structs.Grant{
		CallerServiceID:    caller.ID,
		TargetServiceID:    target.ID,
		Scopes:             structs.ScopeList(in.Scopes),
		LifetimeSeconds:    uint32(lifetime.Seconds()),
		RotateAfterSeconds: uint32(rotateAfter.Seconds()),
		Status:             constants.GrantActive,
	}
	if err := g.repo.Create(ctx, grant); err != nil {
		return nil, err
	}

	e := entry(in.Actor, constants.ActionGrantCreate, constants.TargetGrant,
		strconv.FormatUint(grant.ID, 10))
	e.Metadata = structs.JSONMap{
		"caller":       caller.Name,
		"target":       target.Name,
		"scopes":       in.Scopes,
		"lifetime":     lifetime.String(),
		"rotate_after": rotateAfter.String(),
		"overlap":      (lifetime - rotateAfter).String(),
	}
	e.RequestIP = structs.IPBytes(in.RemoteIP)
	if err := g.audit.Append(ctx, e); err != nil {
		return nil, err
	}

	return g.repo.ByID(ctx, grant.ID)
}

func (g *Grants) ByID(ctx context.Context, id uint64) (*structs.GrantDetail, error) {
	return g.repo.ByID(ctx, id)
}

func (g *Grants) List(ctx context.Context, f structs.GrantFilter) ([]structs.GrantDetail, error) {
	return g.repo.List(ctx, f)
}

// Authorize is the issuance-path check: is there an active grant from caller to
// target, with both services enabled? Phase 2 calls this before minting.
func (g *Grants) Authorize(ctx context.Context, caller *structs.Service, targetName string) (*structs.Grant, *structs.Service, error) {
	target, err := g.registry.ByName(ctx, targetName)
	if err != nil {
		return nil, nil, err
	}
	if !target.IsActive() {
		return nil, nil, apperr.ServiceDisabled.WithMessage("target service %q is disabled", target.Name)
	}

	grant, err := g.repo.ByPair(ctx, caller.ID, target.ID)
	if err != nil {
		if apperr.HasCode(err, apperr.GrantNotFound.Code) {
			return nil, nil, apperr.NoGrant.WithMessage("no grant from %q to %q", caller.Name, target.Name)
		}
		return nil, nil, err
	}
	if !grant.IsActive() {
		return nil, nil, apperr.GrantRevoked
	}
	return grant, target, nil
}

// UpdatePolicy changes scopes and timings.
func (g *Grants) UpdatePolicy(ctx context.Context, in structs.UpdateGrantInput) (*structs.GrantDetail, error) {
	existing, err := g.repo.ByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !existing.IsActive() {
		return nil, apperr.GrantRevoked.WithMessage("cannot update a revoked grant")
	}

	lifetime, rotateAfter, err := resolveTiming(g.policy, in.Lifetime, in.RotateAfter)
	if err != nil {
		return nil, err
	}

	updated := existing.Grant
	updated.Scopes = structs.ScopeList(in.Scopes)
	updated.LifetimeSeconds = uint32(lifetime.Seconds())
	updated.RotateAfterSeconds = uint32(rotateAfter.Seconds())
	if err := g.repo.UpdatePolicy(ctx, &updated); err != nil {
		return nil, err
	}

	e := entry(in.Actor, constants.ActionGrantUpdate, constants.TargetGrant,
		strconv.FormatUint(in.ID, 10))
	e.Metadata = structs.JSONMap{
		"scopes":       in.Scopes,
		"lifetime":     lifetime.String(),
		"rotate_after": rotateAfter.String(),
	}
	if err := g.audit.Append(ctx, e); err != nil {
		return nil, err
	}
	return g.repo.ByID(ctx, in.ID)
}
