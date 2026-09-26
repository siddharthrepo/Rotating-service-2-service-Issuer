package mysql

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type GrantRepo struct{ db *sqlx.DB }

func NewGrantRepo(db *sqlx.DB) *GrantRepo { return &GrantRepo{db: db} }

func (r *GrantRepo) Create(ctx context.Context, g *structs.Grant) error {
	res, err := r.db.NamedExecContext(ctx, `
		INSERT INTO grants (caller_service_id, target_service_id, scopes,
		                    lifetime_seconds, rotate_after_seconds, status)
		VALUES (:caller_service_id, :target_service_id, :scopes,
		        :lifetime_seconds, :rotate_after_seconds, :status)`, g)
	if err != nil {
		if isDuplicate(err, constants.IdxGrantPair) {
			return apperr.GrantExists.Wrap(err)
		}
		if isCheckViolation(err) {
			return apperr.BadRequest.
				WithMessage("grant violates a schema constraint (self-grant, or rotate_after >= lifetime)").
				Wrap(err)
		}
		return fmt.Errorf("insert grant: %w", err)
	}
	id, err := lastInsertID(res, "grant")
	if err != nil {
		return err
	}
	g.ID = id
	return nil
}

func (r *GrantRepo) ByID(ctx context.Context, id uint64) (*structs.GrantDetail, error) {
	var g structs.GrantDetail
	err := r.db.GetContext(ctx, &g, `
		SELECT g.id, g.caller_service_id, g.target_service_id, g.scopes,
		       g.lifetime_seconds, g.rotate_after_seconds, g.status, g.revoked_at,
		       g.revoked_reason, g.created_at, g.updated_at,
		       caller.name AS caller_name,
		       target.name AS target_name
		  FROM grants g
		  JOIN services caller ON caller.id = g.caller_service_id
		  JOIN services target ON target.id = g.target_service_id
		 WHERE g.id = ?`, id)
	if noRows(err) {
		return nil, apperr.GrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select grant by id: %w", err)
	}
	return &g, nil
}

// ByPair is the issuance-path lookup: does caller have a grant to target?
func (r *GrantRepo) ByPair(ctx context.Context, callerID, targetID uint64) (*structs.Grant, error) {
	var g structs.Grant
	err := r.db.GetContext(ctx, &g, `
		SELECT g.id, g.caller_service_id, g.target_service_id, g.scopes,
		       g.lifetime_seconds, g.rotate_after_seconds, g.status, g.revoked_at,
		       g.revoked_reason, g.created_at, g.updated_at
		  FROM grants g
		 WHERE g.caller_service_id = ? AND g.target_service_id = ?`, callerID, targetID)
	if noRows(err) {
		return nil, apperr.GrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select grant by pair: %w", err)
	}
	return &g, nil
}

func (r *GrantRepo) List(ctx context.Context, f structs.GrantFilter) ([]structs.GrantDetail, error) {
	limit, offset := applyPaging(f.Limit, f.Offset)

	query := `
		SELECT g.id, g.caller_service_id, g.target_service_id, g.scopes,
		       g.lifetime_seconds, g.rotate_after_seconds, g.status, g.revoked_at,
		       g.revoked_reason, g.created_at, g.updated_at,
		       caller.name AS caller_name,
		       target.name AS target_name
		  FROM grants g
		  JOIN services caller ON caller.id = g.caller_service_id
		  JOIN services target ON target.id = g.target_service_id
		 WHERE 1 = 1`
	args := []any{}
	if f.CallerID != 0 {
		query += ` AND g.caller_service_id = ?`
		args = append(args, f.CallerID)
	}
	if f.TargetID != 0 {
		query += ` AND g.target_service_id = ?`
		args = append(args, f.TargetID)
	}
	if f.Status != "" {
		query += ` AND g.status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY caller.name, target.name LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	out := []structs.GrantDetail{}
	if err := r.db.SelectContext(ctx, &out, query, args...); err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	return out, nil
}

// UpdatePolicy changes scopes and timings; existing tokens keep their original
// expiry and the new policy applies from the next refresh.
func (r *GrantRepo) UpdatePolicy(ctx context.Context, g *structs.Grant) error {
	res, err := r.db.NamedExecContext(ctx, `
		UPDATE grants
		   SET scopes = :scopes,
		       lifetime_seconds = :lifetime_seconds,
		       rotate_after_seconds = :rotate_after_seconds
		 WHERE id = :id`, g)
	if err != nil {
		if isCheckViolation(err) {
			return apperr.InvalidRotation.Wrap(err)
		}
		return fmt.Errorf("update grant policy: %w", err)
	}
	return requireAffected(res, apperr.GrantNotFound)
}

// SetRevoked marks a grant revoked inside the caller's transaction.
func (r *GrantRepo) SetRevoked(ctx context.Context, tx *sqlx.Tx, id uint64, reason string) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE grants
		   SET status = 'revoked', revoked_at = NOW(), revoked_reason = ?
		 WHERE id = ? AND status = 'active'`, reason, id)
	if err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}
	return requireAffected(res, apperr.GrantNotFound.
		WithMessage("grant %d not found or already revoked", id))
}
