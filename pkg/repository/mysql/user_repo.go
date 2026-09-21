package mysql

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type UserRepo struct{ db *sqlx.DB }

func NewUserRepo(db *sqlx.DB) *UserRepo { return &UserRepo{db: db} }

func (r *UserRepo) Create(ctx context.Context, u *structs.User) error {
	res, err := r.db.NamedExecContext(ctx, `
		INSERT INTO users (email, name, password_hash, role, status)
		VALUES (:email, :name, :password_hash, :role, :status)`, u)
	if err != nil {
		if isDuplicate(err, "uk_users_email") {
			return apperr.Conflict.WithMessage("user %q already exists", u.Email).Wrap(err)
		}
		return fmt.Errorf("insert user: %w", err)
	}
	id, err := lastInsertID(res, "user")
	if err != nil {
		return err
	}
	u.ID = id
	return nil
}

func (r *UserRepo) ByEmail(ctx context.Context, email string) (*structs.User, error) {
	var u structs.User
	err := r.db.GetContext(ctx, &u, `
		SELECT id, email, name, password_hash, role, status, created_at
		  FROM users
		 WHERE email = ?`, email)
	if noRows(err) {
		return nil, apperr.NotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select user by email: %w", err)
	}
	return &u, nil
}

// CreateSession stores the HASH of the cookie value, never the value itself -- the
// same reasoning that applies to tokens.
func (r *UserRepo) CreateSession(ctx context.Context, s *structs.Session) error {
	_, err := r.db.NamedExecContext(ctx, `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES (:id, :user_id, :expires_at)`, s)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// UserBySession resolves a session hash to its user in one query, rejecting expired
// sessions and disabled accounts in the same statement.
func (r *UserRepo) UserBySession(ctx context.Context, sessionHash string, now time.Time) (*structs.User, error) {
	var u structs.User
	err := r.db.GetContext(ctx, &u, `
		SELECT u.id, u.email, u.name, u.password_hash, u.role, u.status, u.created_at
		  FROM sessions s
		  JOIN users u ON u.id = s.user_id
		 WHERE s.id = ? AND s.expires_at > ? AND u.status = 'active'`, sessionHash, now)
	if noRows(err) {
		return nil, apperr.Unauthorized
	}
	if err != nil {
		return nil, fmt.Errorf("select user by session: %w", err)
	}
	return &u, nil
}

func (r *UserRepo) DeleteSession(ctx context.Context, sessionHash string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sessionHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (r *UserRepo) PurgeExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("purge sessions: %w", err)
	}
	return res.RowsAffected()
}
