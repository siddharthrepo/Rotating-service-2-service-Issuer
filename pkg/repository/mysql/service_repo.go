package mysql

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type ServiceRepo struct{ db *sqlx.DB }

func NewServiceRepo(db *sqlx.DB) *ServiceRepo { return &ServiceRepo{db: db} }

func (r *ServiceRepo) Create(ctx context.Context, s *structs.Service) error {
	res, err := r.db.NamedExecContext(ctx, `
		INSERT INTO services (name, client_id, client_secret_hash, owner_team, description, status)
		VALUES (:name, :client_id, :client_secret_hash, :owner_team, :description, :status)`, s)
	if err != nil {
		if isDuplicate(err, constants.IdxServiceName) {
			return apperr.ServiceExists.WithMessage("service %q is already registered", s.Name).Wrap(err)
		}
		return fmt.Errorf("insert service: %w", err)
	}
	id, err := lastInsertID(res, "service")
	if err != nil {
		return err
	}
	s.ID = id
	return nil
}

func (r *ServiceRepo) ByID(ctx context.Context, id uint64) (*structs.Service, error) {
	var s structs.Service
	err := r.db.GetContext(ctx, &s, `
		SELECT id, name, client_id, client_secret_hash, owner_team,
		       description, status, secret_rotated_at, created_at, updated_at
		  FROM services
		 WHERE id = ?`, id)
	if noRows(err) {
		return nil, apperr.ServiceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select service by id: %w", err)
	}
	return &s, nil
}

func (r *ServiceRepo) ByName(ctx context.Context, name string) (*structs.Service, error) {
	var s structs.Service
	err := r.db.GetContext(ctx, &s, `
		SELECT id, name, client_id, client_secret_hash, owner_team,
		       description, status, secret_rotated_at, created_at, updated_at
		  FROM services
		 WHERE name = ?`, name)
	if noRows(err) {
		return nil, apperr.ServiceNotFound.WithMessage("service %q is not registered", name)
	}
	if err != nil {
		return nil, fmt.Errorf("select service by name: %w", err)
	}
	return &s, nil
}

// ByClientID is on the issuance path; client_id is uniquely indexed.
func (r *ServiceRepo) ByClientID(ctx context.Context, clientID string) (*structs.Service, error) {
	var s structs.Service
	err := r.db.GetContext(ctx, &s, `
		SELECT id, name, client_id, client_secret_hash, owner_team,
		       description, status, secret_rotated_at, created_at, updated_at
		  FROM services
		 WHERE client_id = ?`, clientID)
	if noRows(err) {
		return nil, apperr.ServiceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select service by client_id: %w", err)
	}
	return &s, nil
}

func (r *ServiceRepo) List(ctx context.Context, f structs.ServiceFilter) ([]structs.Service, error) {
	limit, offset := applyPaging(f.Limit, f.Offset)

	query := `
		SELECT id, name, client_id, client_secret_hash, owner_team,
		       description, status, secret_rotated_at, created_at, updated_at
		  FROM services
		 WHERE 1 = 1`
	args := []any{}
	if f.OwnerTeam != "" {
		query += ` AND owner_team = ?`
		args = append(args, f.OwnerTeam)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY name LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	out := []structs.Service{}
	if err := r.db.SelectContext(ctx, &out, query, args...); err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	return out, nil
}

func (r *ServiceRepo) UpdateStatus(ctx context.Context, id uint64, status constants.ServiceStatus) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE services SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("update service status: %w", err)
	}
	return requireAffected(res, apperr.ServiceNotFound)
}

func (r *ServiceRepo) UpdateSecret(ctx context.Context, id uint64, hash string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE services
		   SET client_secret_hash = ?, secret_rotated_at = NOW()
		 WHERE id = ?`, hash, id)
	if err != nil {
		return fmt.Errorf("update service secret: %w", err)
	}
	return requireAffected(res, apperr.ServiceNotFound)
}
