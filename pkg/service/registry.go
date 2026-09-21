package service

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strconv"
	"time"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/crypto"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type serviceRepo interface {
	Create(ctx context.Context, s *structs.Service) error
	ByID(ctx context.Context, id uint64) (*structs.Service, error)
	ByName(ctx context.Context, name string) (*structs.Service, error)
	ByClientID(ctx context.Context, clientID string) (*structs.Service, error)
	List(ctx context.Context, f structs.ServiceFilter) ([]structs.Service, error)
	UpdateStatus(ctx context.Context, id uint64, status constants.ServiceStatus) error
	UpdateSecret(ctx context.Context, id uint64, hash string) error
}

// ServiceAuthCache memoises successful client-credential verifications.
type ServiceAuthCache interface {
	Get(ctx context.Context, clientID string) (*structs.CachedAuth, error)
	Set(ctx context.Context, clientID string, v *structs.CachedAuth, ttl time.Duration) error
	Delete(ctx context.Context, clientID string) error
}

// Registry owns service identities: one row per service, never per pod.
type Registry struct {
	repo    serviceRepo
	audit   *Audit
	argon2  structs.Argon2Params
	auth    ServiceAuthCache
	authTTL time.Duration
}

func NewRegistry(repo serviceRepo, audit *Audit, argon2 structs.Argon2Params,
	auth ServiceAuthCache, authTTL time.Duration) *Registry {
	return &Registry{repo: repo, audit: audit, argon2: argon2, auth: auth, authTTL: authTTL}
}

func (r *Registry) Create(ctx context.Context, in structs.CreateServiceInput) (*structs.Credentials, error) {
	if err := validateServiceName(in.Name); err != nil {
		return nil, err
	}

	secret, err := crypto.GenerateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	hash, err := crypto.HashSecret(secret, r.argon2)
	if err != nil {
		return nil, fmt.Errorf("hash secret: %w", err)
	}

	svc := &structs.Service{
		Name:             in.Name,
		ClientID:         crypto.NewID(),
		ClientSecretHash: hash,
		OwnerTeam:        structs.NewNullString(in.OwnerTeam),
		Description:      structs.NewNullString(in.Description),
		Status:           constants.ServiceActive,
	}
	if err := r.repo.Create(ctx, svc); err != nil {
		return nil, err
	}

	svc, err = r.repo.ByID(ctx, svc.ID)
	if err != nil {
		return nil, err
	}

	e := entry(in.Actor, constants.ActionServiceCreate, constants.TargetService,
		strconv.FormatUint(svc.ID, 10))
	e.Metadata = structs.JSONMap{"name": svc.Name, "owner_team": in.OwnerTeam}
	e.RequestIP = structs.IPBytes(in.RemoteIP)
	if err := r.audit.Append(ctx, e); err != nil {
		return nil, err
	}

	return &structs.Credentials{Service: svc, ClientID: svc.ClientID, ClientSecret: secret}, nil
}

func (r *Registry) ByID(ctx context.Context, id uint64) (*structs.Service, error) {
	return r.repo.ByID(ctx, id)
}

func (r *Registry) ByName(ctx context.Context, name string) (*structs.Service, error) {
	return r.repo.ByName(ctx, name)
}

func (r *Registry) List(ctx context.Context, f structs.ServiceFilter) ([]structs.Service, error) {
	return r.repo.List(ctx, f)
}

// Authenticate verifies a bootstrap credential -- the one long-lived secret in the
// system, which is why it is argon2id rather than a fast hash.
func (r *Registry) Authenticate(ctx context.Context, clientID, secret string) (*structs.Service, error) {

	presented := crypto.HashToken(secret)
	if cached, err := r.auth.Get(ctx, clientID); err == nil && cached != nil {
		if subtle.ConstantTimeCompare([]byte(cached.SecretSHA256), []byte(presented)) == 1 {
			if !cached.Active {
				return nil, apperr.ServiceDisabled.WithMessage("service %q is disabled", cached.Name)
			}
			return cached.ToService(), nil
		}

	}

	svc, err := r.repo.ByClientID(ctx, clientID)
	if err != nil {
		if apperr.HasCode(err, apperr.ServiceNotFound.Code) {

			_, _ = crypto.VerifySecret(secret, constants.DummyArgon2Hash)
			return nil, apperr.InvalidClient
		}
		return nil, err
	}

	ok, err := crypto.VerifySecret(secret, svc.ClientSecretHash)
	if err != nil {
		return nil, fmt.Errorf("verify client secret: %w", err)
	}
	if !ok {
		return nil, apperr.InvalidClient
	}
	if !svc.IsActive() {
		return nil, apperr.ServiceDisabled.WithMessage("service %q is disabled", svc.Name)
	}

	_ = r.auth.Set(ctx, clientID, &structs.CachedAuth{
		SecretSHA256: presented,
		ServiceID:    svc.ID,
		Name:         svc.Name,
		ClientID:     svc.ClientID,
		Active:       true,
	}, r.authTTL)

	return svc, nil
}

func (r *Registry) SetStatus(ctx context.Context, id uint64, status constants.ServiceStatus, actor structs.Actor) error {
	if status != constants.ServiceActive && status != constants.ServiceDisabled {
		return apperr.BadRequest.WithMessage("status must be active or disabled")
	}
	if err := r.repo.UpdateStatus(ctx, id, status); err != nil {
		return err
	}

	if svc, err := r.repo.ByID(ctx, id); err == nil {
		_ = r.auth.Delete(ctx, svc.ClientID)
	}
	e := entry(actor, constants.ActionServiceUpdate, constants.TargetService,
		strconv.FormatUint(id, 10))
	e.Metadata = structs.JSONMap{"status": string(status)}
	return r.audit.Append(ctx, e)
}

// RotateSecret issues a new bootstrap credential.
func (r *Registry) RotateSecret(ctx context.Context, id uint64, actor structs.Actor) (*structs.Credentials, error) {
	secret, err := crypto.GenerateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	hash, err := crypto.HashSecret(secret, r.argon2)
	if err != nil {
		return nil, fmt.Errorf("hash secret: %w", err)
	}
	if err := r.repo.UpdateSecret(ctx, id, hash); err != nil {
		return nil, err
	}

	if prior, err := r.repo.ByID(ctx, id); err == nil {
		_ = r.auth.Delete(ctx, prior.ClientID)
	}

	svc, err := r.repo.ByID(ctx, id)
	if err != nil {
		return nil, err
	}

	e := entry(actor, constants.ActionServiceRotateSecret, constants.TargetService,
		strconv.FormatUint(id, 10))
	if err := r.audit.Append(ctx, e); err != nil {
		return nil, err
	}
	return &structs.Credentials{Service: svc, ClientID: svc.ClientID, ClientSecret: secret}, nil
}
