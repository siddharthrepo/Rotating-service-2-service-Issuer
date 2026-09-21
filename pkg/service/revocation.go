package service

import (
	"context"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type revocationTokenRepo interface {
	tokenRepo
	RevokeLiveByGrant(ctx context.Context, tx *sqlx.Tx, grantID uint64, at time.Time) ([]string, error)
}

type revocationGrantRepo interface {
	ByID(ctx context.Context, id uint64) (*structs.GrantDetail, error)
	SetRevoked(ctx context.Context, tx *sqlx.Tx, id uint64, reason string) error
}

// Revocation implements the two operator actions.
type Revocation struct {
	tokens revocationTokenRepo
	grants revocationGrantRepo
	cache  CurrentTokens
	tcache TokenCache
	tx     txRunner
	audit  *Audit
	log    *zap.Logger
	now    func() time.Time
}

func NewRevocation(tokens revocationTokenRepo, grants revocationGrantRepo, cache CurrentTokens,
	tcache TokenCache, tx txRunner, audit *Audit, log *zap.Logger) *Revocation {
	return &Revocation{
		tokens: tokens, grants: grants, cache: cache, tcache: tcache,
		tx: tx, audit: audit, log: log, now: time.Now,
	}
}

// RevokeGrant kills every live token and blocks further issuance.
func (r *Revocation) RevokeGrant(ctx context.Context, grantID uint64, actor structs.Actor, reason string) (*structs.RevokeResponse, error) {
	detail, err := r.grants.ByID(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if !detail.IsActive() {
		return nil, apperr.GrantRevoked.WithMessage("grant %d is already revoked", grantID)
	}

	var hashes []string

	err = r.tx.WithTx(ctx, func(tx *sqlx.Tx) error {
		if err := r.grants.SetRevoked(ctx, tx, grantID, reason); err != nil {
			return err
		}
		hashes, err = r.tokens.RevokeLiveByGrant(ctx, tx, grantID, r.now())
		if err != nil {
			return err
		}
		e := entry(actor, constants.ActionGrantRevoke, constants.TargetGrant,
			strconv.FormatUint(grantID, 10))
		e.Reason = structs.NewNullString(reason)
		e.Metadata = structs.JSONMap{
			"caller":         detail.CallerName,
			"target":         detail.TargetName,
			"tokens_revoked": len(hashes),
		}
		return r.audit.AppendTx(ctx, tx, e)
	})
	if err != nil {
		return nil, err
	}

	if err := r.invalidate(ctx, grantID, hashes); err != nil {
		return nil, err
	}

	return &structs.RevokeResponse{
		GrantID:       grantID,
		Status:        string(constants.GrantRevoked),
		TokensRevoked: len(hashes),
		Reason:        reason,
	}, nil
}

// ForceRotate kills the live tokens and mints a replacement atomically.
func (r *Revocation) ForceRotate(ctx context.Context, grantID uint64, actor structs.Actor, reason string) (*structs.RotateResponse, error) {
	detail, err := r.grants.ByID(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if !detail.IsActive() {
		return nil, apperr.GrantRevoked.WithMessage("cannot rotate a revoked grant")
	}

	var (
		hashes    []string
		issued    *structs.Token
		plaintext string
	)
	err = r.tx.WithTx(ctx, func(tx *sqlx.Tx) error {
		if err := r.tokens.LockGrant(ctx, tx, grantID); err != nil {
			return err
		}

		hashes, err = r.tokens.RevokeLiveByGrant(ctx, tx, grantID, r.now())
		if err != nil {
			return err
		}
		issued, plaintext, err = MintToken(ctx, tx, r.tokens, r.audit, MintParams{
			Grant:      &detail.Grant,
			CallerName: detail.CallerName,
			TargetName: detail.TargetName,
			Now:        r.now(),
		})
		if err != nil {
			return err
		}
		e := entry(actor, constants.ActionGrantRotate, constants.TargetGrant,
			strconv.FormatUint(grantID, 10))
		e.Reason = structs.NewNullString(reason)
		e.Metadata = structs.JSONMap{
			"caller":         detail.CallerName,
			"target":         detail.TargetName,
			"tokens_revoked": len(hashes),
			"new_token_jti":  issued.JTI,
		}
		return r.audit.AppendTx(ctx, tx, e)
	})
	if err != nil {
		return nil, err
	}

	if err := r.invalidate(ctx, grantID, hashes); err != nil {
		return nil, err
	}

	_ = r.cache.Set(ctx, grantID, &structs.CurrentToken{
		Token:     plaintext,
		IssuedAt:  issued.IssuedAt,
		ExpiresAt: issued.ExpiresAt,
	}, detail.RotateAfter())

	return &structs.RotateResponse{
		GrantID:       grantID,
		Status:        string(constants.GrantActive),
		TokensRevoked: len(hashes),
		NewTokenJTI:   issued.JTI,
		ExpiresAt:     issued.ExpiresAt,
		Reason:        reason,
	}, nil
}

func (r *Revocation) invalidate(ctx context.Context, grantID uint64, hashes []string) error {
	err := retry(ctx, constants.InvalidationAttempts, constants.InvalidationBackoff, func() error {
		if err := r.tcache.Delete(ctx, hashes...); err != nil {
			return err
		}
		return r.cache.Delete(ctx, grantID)
	})
	if err == nil {
		return nil
	}

	r.log.Error("cache invalidation failed after revocation",
		zap.Uint64("grant_id", grantID),
		zap.Int("tokens", len(hashes)),
		zap.Error(err))

	return apperr.RevokedButCacheUnconfirmed.Wrap(err)
}
