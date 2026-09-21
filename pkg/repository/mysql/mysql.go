// Package mysql implements the repository layer.
package mysql

import (
	"context"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

func Open(cfg structs.MySQL) (*sqlx.DB, error) {
	db, err := sqlx.Open("mysql", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open mysql: %w", err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping mysql: %w", err)
	}
	return db, nil
}

// TxManager lets the service layer run a unit of work in a transaction without
// holding a *sqlx.DB itself.
type TxManager struct{ db *sqlx.DB }

func NewTxManager(db *sqlx.DB) *TxManager { return &TxManager{db: db} }

// The parameter is the literal func type rather than TxFn so that consumers can
// declare their own minimal interface for this without importing this package.
func (m *TxManager) WithTx(ctx context.Context, fn func(tx *sqlx.Tx) error) error {
	return WithTx(ctx, m.db, fn)
}

// TxFn runs inside a transaction.
type TxFn func(tx *sqlx.Tx) error

// WithTx wraps a unit of work.
func WithTx(ctx context.Context, db *sqlx.DB, fn TxFn) (err error) {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}
