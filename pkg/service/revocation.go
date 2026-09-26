package service

import (
	"context"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type revocationTokenRepo interface {
	tokenRepo
	LiveByService(ctx context.Context, serviceID uint64, at time.Time) ([]structs.RevokedToken, error)
	RevokeLiveByGrant(ctx context.Context, tx *sqlx.Tx, grantID uint64, at time.Time) ([]structs.RevokedToken, error)
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

	var killed []structs.RevokedToken

	err = r.tx.WithTx(ctx, func(tx *sqlx.Tx) error {
		if err := r.grants.SetRevoked(ctx, tx, grantID, reason); err != nil {
			return err
		}
		killed, err = r.tokens.RevokeLiveByGrant(ctx, tx, grantID, r.now())
		if err != nil {
			return err
		}
		e := entry(actor, constants.ActionGrantRevoke, constants.TargetGrant,
			strconv.FormatUint(grantID, 10))
		e.Reason = structs.NewNullString(reason)
		e.Metadata = structs.JSONMap{
			"caller":         detail.CallerName,
			"target":         detail.TargetName,
			"tokens_revoked": len(killed),
		}
		return r.audit.AppendTx(ctx, tx, e)
	})
	if err != nil {
		return nil, err
	}

	if err := r.invalidate(ctx, grantID, killed); err != nil {
		return nil, err
	}

	return &structs.RevokeResponse{
		GrantID:       grantID,
		Status:        string(constants.GrantRevoked),
		TokensRevoked: len(killed),
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
		killed    []structs.RevokedToken
		issued    *structs.Token
		plaintext string
	)
	err = r.tx.WithTx(ctx, func(tx *sqlx.Tx) error {
		if err := r.tokens.LockGrant(ctx, tx, grantID); err != nil {
			return err
		}

		killed, err = r.tokens.RevokeLiveByGrant(ctx, tx, grantID, r.now())
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
			"tokens_revoked": len(killed),
			"new_token_jti":  issued.JTI,
		}
		return r.audit.AppendTx(ctx, tx, e)
	})
	if err != nil {
		return nil, err
	}

	if err := r.invalidate(ctx, grantID, killed); err != nil {
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
		TokensRevoked: len(killed),
		NewTokenJTI:   issued.JTI,
		ExpiresAt:     issued.ExpiresAt,
		Reason:        reason,
	}, nil
}

// invalidate writes a tombstone for each killed token.
//
// It does NOT delete. Deleting loses a race: a reader that missed the cache and
// read MySQL before this revocation committed can repopulate the key after the
// delete lands, leaving a revoked token cached as valid for the rest of its
// TTL. Writing Revoked:true with an unconditional Set, while the read path
// repopulates with SetIfAbsent, makes the revoker win either ordering.
//
// The tombstone inherits the token's own expiry, so it disappears exactly when
// the token would have become useless anyway.
func (r *Revocation) invalidate(ctx context.Context, grantID uint64, killed []structs.RevokedToken) error {
	err := retry(ctx, constants.InvalidationAttempts, constants.InvalidationBackoff, func() error {
		if err := r.tombstone(ctx, killed, constants.ReasonRevoked); err != nil {
			return err
		}
		return r.cache.Delete(ctx, grantID)
	})
	if err == nil {
		return nil
	}

	r.log.Error("cache invalidation failed after revocation",
		zap.Uint64("grant_id", grantID),
		zap.Int("tokens", len(killed)),
		zap.Error(err))

	return apperr.RevokedButCacheUnconfirmed.Wrap(err)
}

// tombstone marks each hash revoked in the shared cache.
func (r *Revocation) tombstone(ctx context.Context, killed []structs.RevokedToken, reason string) error {
	now := r.now()
	for _, k := range killed {
		ttl := k.ExpiresAt.Sub(now)
		if ttl <= 0 {
			continue // already expired; nothing can serve it
		}
		if err := r.tcache.Set(ctx, k.TokenHash, structs.Tombstone(k.ExpiresAt, reason), ttl); err != nil {
			return err
		}
	}
	return nil
}

// RevokeTokensForService tombstones every live token where the service is
// either endpoint.
//
// Disabling a service has to do this. A cached record carries the endpoints'
// statuses as they were when it was written, so without invalidation a disabled
// service's tokens keep validating until those entries expire -- up to a full
// token lifetime after the operator believed access was cut.
func (r *Revocation) RevokeTokensForService(ctx context.Context, serviceID uint64) (int, error) {
	killed, err := r.tokens.LiveByService(ctx, serviceID, r.now())
	if err != nil {
		return 0, err
	}
	if len(killed) == 0 {
		return 0, nil
	}
	if err := r.tombstone(ctx, killed, constants.ReasonServiceDisabled); err != nil {
		r.log.Error("invalidating tokens for a disabled service",
			zap.Uint64("service_id", serviceID), zap.Error(err))
		return 0, apperr.RevokedButCacheUnconfirmed.Wrap(err)
	}

	// Clear the current-token key for every affected grant as well.
	//
	// Without this, re-enabling the service within rotate_after hands callers
	// back the same tombstoned token: the SDK gets a 401, refreshes, receives
	// the identical dead token, and loops until the key expires.
	seen := make(map[uint64]struct{}, len(killed))
	for _, k := range killed {
		if _, done := seen[k.GrantID]; done {
			continue
		}
		seen[k.GrantID] = struct{}{}
		if err := r.cache.Delete(ctx, k.GrantID); err != nil {
			r.log.Error("clearing current-token key for a disabled service",
				zap.Uint64("grant_id", k.GrantID), zap.Error(err))
			return 0, apperr.RevokedButCacheUnconfirmed.Wrap(err)
		}
	}
	return len(killed), nil
}
