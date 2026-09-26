package service

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/crypto"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type userRepo interface {
	Create(ctx context.Context, u *structs.User) error
	ByEmail(ctx context.Context, email string) (*structs.User, error)
	CreateSession(ctx context.Context, s *structs.Session) error
	UserBySession(ctx context.Context, sessionHash string, now time.Time) (*structs.User, error)
	DeleteSession(ctx context.Context, sessionHash string) error
	PurgeExpiredSessions(ctx context.Context, now time.Time) (int64, error)
}

// Auth handles human operators.
type Auth struct {
	repo   userRepo
	audit  *Audit
	argon2 structs.Argon2Params
	now    func() time.Time
}

func NewAuth(repo userRepo, audit *Audit, argon2 structs.Argon2Params) *Auth {
	return &Auth{repo: repo, audit: audit, argon2: argon2, now: time.Now}
}

// CreateUser registers an operator.
func (a *Auth) CreateUser(ctx context.Context, email, name, password string, role constants.UserRole) (*structs.User, error) {
	if len(password) < constants.MinPasswordLen {
		return nil, apperr.BadRequest.WithMessage(
			"password must be at least %d characters", constants.MinPasswordLen)
	}
	switch role {
	case constants.RoleAdmin, constants.RoleOperator, constants.RoleViewer:
	default:
		return nil, apperr.BadRequest.WithMessage("role must be admin, operator or viewer")
	}

	hash, err := crypto.HashSecret(password, a.argon2)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	u := &structs.User{
		Email: email, Name: name, PasswordHash: hash,
		Role: role, Status: constants.ServiceActive,
	}
	if err := a.repo.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// Login verifies a password and issues a session.
func (a *Auth) Login(ctx context.Context, email, password, remoteIP string) (string, *structs.User, error) {
	user, err := a.repo.ByEmail(ctx, email)
	if err != nil {
		if apperr.HasCode(err, apperr.NotFound.Code) {

			_, _ = crypto.VerifySecret(password, constants.DummyArgon2Hash)
			return "", nil, apperr.Unauthorized.WithMessage("invalid email or password")
		}
		return "", nil, err
	}

	ok, err := crypto.VerifySecret(password, user.PasswordHash)
	if err != nil {
		return "", nil, fmt.Errorf("verify password: %w", err)
	}
	if !ok || !user.IsActive() {
		return "", nil, apperr.Unauthorized.WithMessage("invalid email or password")
	}

	raw, err := crypto.GenerateClientSecret()
	if err != nil {
		return "", nil, fmt.Errorf("generate session: %w", err)
	}
	session := &structs.Session{
		ID:        crypto.HashToken(raw),
		UserID:    user.ID,
		ExpiresAt: a.now().Add(constants.SessionLifetime),
	}
	if err := a.repo.CreateSession(ctx, session); err != nil {
		return "", nil, err
	}

	e := entry(structs.Actor{Type: constants.ActorUser, ID: user.Email},
		constants.ActionUserLogin, constants.TargetUser, strconv.FormatUint(user.ID, 10))
	e.RequestIP = structs.IPBytes(remoteIP)
	if err := a.audit.Append(ctx, e); err != nil {
		return "", nil, err
	}

	return raw, user, nil
}

// Resolve turns a cookie value into the operator behind it.
func (a *Auth) Resolve(ctx context.Context, rawCookie string) (*structs.User, error) {
	if rawCookie == "" {
		return nil, apperr.Unauthorized
	}
	return a.repo.UserBySession(ctx, crypto.HashToken(rawCookie), a.now())
}

func (a *Auth) Logout(ctx context.Context, rawCookie string, user *structs.User) error {
	if user != nil {
		e := entry(structs.Actor{Type: constants.ActorUser, ID: user.Email},
			constants.ActionUserLogout, constants.TargetUser, strconv.FormatUint(user.ID, 10))
		_ = a.audit.Append(ctx, e)
	}
	return a.repo.DeleteSession(ctx, crypto.HashToken(rawCookie))
}

func (a *Auth) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	return a.repo.PurgeExpiredSessions(ctx, a.now())
}
