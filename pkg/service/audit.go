// Package service holds the business rules.
package service

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type auditRepo interface {
	Append(ctx context.Context, e *structs.AuditEntry) error
	AppendTx(ctx context.Context, tx *sqlx.Tx, e *structs.AuditEntry) error
	List(ctx context.Context, f structs.AuditFilter) ([]structs.AuditEntry, error)
}

type Audit struct{ repo auditRepo }

func NewAudit(repo auditRepo) *Audit { return &Audit{repo: repo} }

func (a *Audit) Append(ctx context.Context, e *structs.AuditEntry) error {
	return a.repo.Append(ctx, e)
}

func (a *Audit) AppendTx(ctx context.Context, tx *sqlx.Tx, e *structs.AuditEntry) error {
	return a.repo.AppendTx(ctx, tx, e)
}

func (a *Audit) List(ctx context.Context, f structs.AuditFilter) ([]structs.AuditEntry, error) {
	return a.repo.List(ctx, f)
}
