package mysql

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type AuditRepo struct{ db *sqlx.DB }

func NewAuditRepo(db *sqlx.DB) *AuditRepo { return &AuditRepo{db: db} }

// namedExecer lets an append run either standalone or inside a caller's
// transaction, so an audit row commits atomically with the mutation it records.
type namedExecer interface {
	NamedExecContext(ctx context.Context, query string, arg any) (sql.Result, error)
}

func (r *AuditRepo) Append(ctx context.Context, e *structs.AuditEntry) error {
	return appendWith(ctx, r.db, e)
}

func (r *AuditRepo) AppendTx(ctx context.Context, tx *sqlx.Tx, e *structs.AuditEntry) error {
	return appendWith(ctx, tx, e)
}

func (r *AuditRepo) List(ctx context.Context, f structs.AuditFilter) ([]structs.AuditEntry, error) {
	limit, offset := applyPaging(f.Limit, f.Offset)

	query := `
		SELECT id, actor_type, actor_id, action, target_type, target_id,
		       reason, metadata, request_ip, created_at
		  FROM audit_log
		 WHERE 1 = 1`
	args := []any{}
	if f.ActorID != "" {
		query += ` AND actor_id = ?`
		args = append(args, f.ActorID)
	}
	if f.Action != "" {
		query += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.TargetType != "" {
		query += ` AND target_type = ?`
		args = append(args, f.TargetType)
	}
	if f.TargetID != "" {
		query += ` AND target_id = ?`
		args = append(args, f.TargetID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	out := []structs.AuditEntry{}
	if err := r.db.SelectContext(ctx, &out, query, args...); err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	return out, nil
}

func appendWith(ctx context.Context, ex namedExecer, e *structs.AuditEntry) error {
	_, err := ex.NamedExecContext(ctx, `
		INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id,
		                       reason, metadata, request_ip)
		VALUES (:actor_type, :actor_id, :action, :target_type, :target_id,
		        :reason, :metadata, :request_ip)`, e)
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}
