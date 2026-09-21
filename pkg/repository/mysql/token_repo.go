package mysql

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type TokenRepo struct{ db *sqlx.DB }

func NewTokenRepo(db *sqlx.DB) *TokenRepo { return &TokenRepo{db: db} }

func (r *TokenRepo) DB() *sqlx.DB { return r.db }

// ByHash is the validation lookup, resolving the token, its grant and both
// endpoints in one round trip.
func (r *TokenRepo) ByHash(ctx context.Context, hash string) (*structs.TokenDetail, error) {
	var t structs.TokenDetail
	err := r.db.GetContext(ctx, &t, `
		SELECT t.id, t.jti, t.grant_id, t.token_hash, t.issued_at,
		       t.expires_at, t.revoked_at, t.superseded_at, t.issued_to_ip,
		       g.status  AS grant_status,
		       g.scopes  AS scopes,
		       caller.name   AS caller_name,
		       caller.status AS caller_status,
		       target.name   AS target_name,
		       target.status AS target_status
		  FROM tokens t
		  JOIN grants   g      ON g.id = t.grant_id
		  JOIN services caller ON caller.id = g.caller_service_id
		  JOIN services target ON target.id = g.target_service_id
		 WHERE t.token_hash = ?`, hash)
	if noRows(err) {
		return nil, apperr.NotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select token by hash: %w", err)
	}
	return &t, nil
}

// LockGrant takes a row lock on the grant, serialising issuance for it.
func (r *TokenRepo) LockGrant(ctx context.Context, tx *sqlx.Tx, grantID uint64) error {
	var id uint64
	err := tx.GetContext(ctx, &id, `
		SELECT id FROM grants WHERE id = ? FOR UPDATE`, grantID)
	if noRows(err) {
		return apperr.GrantNotFound
	}
	if err != nil {
		return fmt.Errorf("lock grant: %w", err)
	}
	return nil
}

// CurrentByGrant returns the token new callers are currently being handed.
func (r *TokenRepo) CurrentByGrant(ctx context.Context, tx *sqlx.Tx, grantID uint64) (*structs.Token, error) {
	var t structs.Token
	err := tx.GetContext(ctx, &t, `
		SELECT t.id, t.jti, t.grant_id, t.token_hash, t.issued_at,
		       t.expires_at, t.revoked_at, t.superseded_at, t.issued_to_ip
		  FROM tokens t
		 WHERE t.current_grant_id = ?`, grantID)
	if noRows(err) {
		return nil, apperr.NotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select current token: %w", err)
	}
	return &t, nil
}

// Supersede marks the grant's current token as no longer the one handed out; it
// stays valid until its own expires_at, which is the overlap window.
func (r *TokenRepo) Supersede(ctx context.Context, tx *sqlx.Tx, grantID uint64) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE tokens
		   SET superseded_at = NOW(3)
		 WHERE current_grant_id = ?`, grantID)
	if err != nil {
		return fmt.Errorf("supersede current token: %w", err)
	}
	return nil
}

func (r *TokenRepo) Create(ctx context.Context, tx *sqlx.Tx, t *structs.Token) error {
	res, err := tx.NamedExecContext(ctx, `
		INSERT INTO tokens (jti, grant_id, token_hash, expires_at, issued_to_ip)
		VALUES (:jti, :grant_id, :token_hash, :expires_at, :issued_to_ip)`, t)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	id, err := lastInsertID(res, "token")
	if err != nil {
		return err
	}
	t.ID = id
	return nil
}

// ByID re-reads a token so the caller sees server-assigned columns.
func (r *TokenRepo) ByID(ctx context.Context, tx *sqlx.Tx, id uint64) (*structs.Token, error) {
	var t structs.Token
	err := tx.GetContext(ctx, &t, `
		SELECT t.id, t.jti, t.grant_id, t.token_hash, t.issued_at,
		       t.expires_at, t.revoked_at, t.superseded_at, t.issued_to_ip
		  FROM tokens t
		 WHERE t.id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("select token by id: %w", err)
	}
	return &t, nil
}

// RevokeLiveByGrant revokes every still-usable token for a grant and returns
// their hashes, so the caller knows which cache keys to invalidate.
func (r *TokenRepo) RevokeLiveByGrant(ctx context.Context, tx *sqlx.Tx, grantID uint64, at time.Time) ([]string, error) {
	hashes := []string{}
	err := tx.SelectContext(ctx, &hashes, `
		SELECT token_hash
		  FROM tokens
		 WHERE grant_id = ? AND revoked_at IS NULL AND expires_at > ?
		   FOR UPDATE`, grantID, at)
	if err != nil {
		return nil, fmt.Errorf("select live tokens for revocation: %w", err)
	}
	if len(hashes) == 0 {
		return hashes, nil
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE tokens
		   SET revoked_at = ?
		 WHERE grant_id = ? AND revoked_at IS NULL AND expires_at > ?`,
		at, grantID, at); err != nil {
		return nil, fmt.Errorf("revoke live tokens: %w", err)
	}
	return hashes, nil
}

// LiveByGrant lists tokens for a grant that have not expired or been revoked.
func (r *TokenRepo) LiveByGrant(ctx context.Context, grantID uint64) ([]structs.Token, error) {
	out := []structs.Token{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT t.id, t.jti, t.grant_id, t.token_hash, t.issued_at,
		       t.expires_at, t.revoked_at, t.superseded_at, t.issued_to_ip
		  FROM tokens t
		 WHERE t.grant_id = ? AND t.revoked_at IS NULL AND t.expires_at > NOW(3)
		 ORDER BY t.issued_at DESC`, grantID)
	if err != nil {
		return nil, fmt.Errorf("list live tokens: %w", err)
	}
	return out, nil
}
