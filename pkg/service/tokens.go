package service

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/sync/singleflight"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/crypto"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type tokenRepo interface {
	ByHash(ctx context.Context, hash string) (*structs.TokenDetail, error)
	LockGrant(ctx context.Context, tx *sqlx.Tx, grantID uint64) error
	CurrentByGrant(ctx context.Context, tx *sqlx.Tx, grantID uint64) (*structs.Token, error)
	Supersede(ctx context.Context, tx *sqlx.Tx, grantID uint64) error
	Create(ctx context.Context, tx *sqlx.Tx, t *structs.Token) error
	ByID(ctx context.Context, tx *sqlx.Tx, id uint64) (*structs.Token, error)
}

// CurrentTokens caches the plaintext token currently being handed out for a grant.
type CurrentTokens interface {
	Get(ctx context.Context, grantID uint64) (*structs.CurrentToken, error)
	Set(ctx context.Context, grantID uint64, t *structs.CurrentToken, ttl time.Duration) error
	Delete(ctx context.Context, grantID uint64) error
}

// TokenCache fronts the validation lookup.
type TokenCache interface {
	Get(ctx context.Context, hash string) (*structs.CachedToken, error)
	Set(ctx context.Context, hash string, v *structs.CachedToken, ttl time.Duration) error
	Delete(ctx context.Context, hashes ...string) error
}

type txRunner interface {
	WithTx(ctx context.Context, fn func(tx *sqlx.Tx) error) error
}

// Tokens issues and validates tokens.
type Tokens struct {
	repo    tokenRepo
	grants  *Grants
	cache   CurrentTokens
	tokens  TokenCache
	tx      txRunner
	audit   *Audit
	now     func() time.Time
	stats   StatsRecorder
	negTTL  time.Duration
	lookups singleflight.Group
	minting singleflight.Group
	onCache func(hit bool, err error)
}

func NewTokens(repo tokenRepo, grants *Grants, cache CurrentTokens, tokens TokenCache,
	tx txRunner, audit *Audit, stats StatsRecorder, negTTL time.Duration) *Tokens {
	return &Tokens{
		repo: repo, grants: grants, cache: cache, tokens: tokens,
		tx: tx, audit: audit, stats: stats, now: time.Now, negTTL: negTTL,
	}
}

type IssueInput struct {
	Caller     *structs.Service
	TargetName string
	RemoteIP   string
}

// IssueResult reports whether a new token was minted or an existing one reused, so
// the controller can answer 201 or 200.
type IssueResult struct {
	Response *structs.TokenResponse
	Minted   bool
}

// Issue is get-or-create, not always-create.
func (t *Tokens) Issue(ctx context.Context, in IssueInput) (*IssueResult, error) {
	grant, target, err := t.grants.Authorize(ctx, in.Caller, in.TargetName)
	if err != nil {
		return nil, err
	}

	if cached := t.reusable(ctx, grant); cached != nil {
		return &IssueResult{Response: t.response(cached, grant, target.Name), Minted: false}, nil
	}

	v, err, shared := t.minting.Do(strconv.FormatUint(grant.ID, 10), func() (any, error) {
		return t.mint(ctx, grant, target.Name, in)
	})
	if err != nil {
		return nil, err
	}
	out := v.(*IssueResult)

	return &IssueResult{Response: out.Response, Minted: out.Minted && !shared}, nil
}

func (t *Tokens) mint(ctx context.Context, grant *structs.Grant, targetName string, in IssueInput) (*IssueResult, error) {
	var (
		issued    *structs.Token
		plaintext string
	)
	err := t.tx.WithTx(ctx, func(tx *sqlx.Tx) error {

		if err := t.repo.LockGrant(ctx, tx, grant.ID); err != nil {
			return err
		}
		var err error
		issued, plaintext, err = MintToken(ctx, tx, t.repo, t.audit, MintParams{
			Grant:      grant,
			CallerName: in.Caller.Name,
			TargetName: targetName,
			RemoteIP:   in.RemoteIP,
			Now:        t.now(),
		})
		return err
	})
	if err != nil {
		return nil, err
	}

	current := &structs.CurrentToken{
		Token:     plaintext,
		IssuedAt:  issued.IssuedAt,
		ExpiresAt: issued.ExpiresAt,
	}

	_ = t.cache.Set(ctx, grant.ID, current, grant.RotateAfter())

	return &IssueResult{Response: t.response(current, grant, targetName), Minted: true}, nil
}

// MintParams are the inputs to a single token creation.
type MintParams struct {
	Grant      *structs.Grant
	CallerName string
	TargetName string
	RemoteIP   string
	Now        time.Time
}

// MintToken creates one token inside an existing transaction and returns the row
// plus its plaintext.
func MintToken(ctx context.Context, tx *sqlx.Tx, repo tokenRepo, audit *Audit, p MintParams) (*structs.Token, string, error) {
	plaintext, hash, err := crypto.GenerateToken()
	if err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}

	if err := repo.Supersede(ctx, tx, p.Grant.ID); err != nil {
		return nil, "", err
	}

	tok := &structs.Token{
		JTI:        crypto.NewID(),
		GrantID:    p.Grant.ID,
		TokenHash:  hash,
		ExpiresAt:  p.Now.Add(p.Grant.Lifetime()),
		IssuedToIP: structs.IPBytes(p.RemoteIP),
	}
	if err := repo.Create(ctx, tx, tok); err != nil {
		return nil, "", err
	}

	issued, err := repo.ByID(ctx, tx, tok.ID)
	if err != nil {
		return nil, "", err
	}

	e := entry(
		structs.Actor{Type: constants.ActorService, ID: p.CallerName},
		constants.ActionTokenIssue, constants.TargetToken, issued.JTI)
	e.Metadata = structs.JSONMap{
		"caller":   p.CallerName,
		"target":   p.TargetName,
		"grant_id": p.Grant.ID,
		"lifetime": p.Grant.Lifetime().String(),
	}
	e.RequestIP = structs.IPBytes(p.RemoteIP)
	if err := audit.AppendTx(ctx, tx, e); err != nil {
		return nil, "", err
	}
	return issued, plaintext, nil
}

// Introspect answers whether// Introspect answers whether a presented token is
// usable by the asking service.
func (t *Tokens) Introspect(ctx context.Context, asker *structs.Service, token string) (*structs.IntrospectResponse, error) {
	cached, err := t.lookup(ctx, crypto.HashToken(token))
	if err != nil {
		return nil, err
	}

	active, reason := cached.Validate(t.now(), asker.Name)
	if cached.GrantID != 0 {
		t.stats.Record(ctx, cached.GrantID, active)
	}

	if !active {

		return &structs.IntrospectResponse{Active: false, Reason: reason}, nil
	}

	issuedAt, expiresAt := cached.IssuedAt, cached.ExpiresAt
	return &structs.IntrospectResponse{
		Active:    true,
		Caller:    cached.Caller,
		Target:    cached.Target,
		Scopes:    scopesOrEmpty(cached.Scopes),
		JTI:       cached.JTI,
		IssuedAt:  &issuedAt,
		ExpiresAt: &expiresAt,
	}, nil
}

func (t *Tokens) lookup(ctx context.Context, hash string) (*structs.CachedToken, error) {
	if hit, err := t.tokens.Get(ctx, hash); err == nil && hit != nil {
		t.observe(true, nil)
		return hit, nil
	} else if err != nil {

		t.observe(false, err)
	}

	v, err, _ := t.lookups.Do(hash, func() (any, error) {
		detail, err := t.repo.ByHash(ctx, hash)
		if err != nil {
			if apperr.HasCode(err, apperr.NotFound.Code) {

				miss := &structs.CachedToken{NotFound: true}
				_ = t.tokens.Set(ctx, hash, miss, t.negTTL)
				return miss, nil
			}
			return nil, err
		}

		out := detail.ToCached()

		_ = t.tokens.Set(ctx, hash, out, time.Until(out.ExpiresAt))
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*structs.CachedToken), nil
}

func (t *Tokens) observe(hit bool, err error) {
	if t.onCache != nil {
		t.onCache(hit, err)
	}
}

func (t *Tokens) reusable(ctx context.Context, grant *structs.Grant) *structs.CurrentToken {
	cached, err := t.cache.Get(ctx, grant.ID)
	if err != nil || cached == nil {
		return nil
	}

	if !t.now().Before(cached.IssuedAt.Add(grant.RotateAfter())) {
		return nil
	}
	return cached
}

func (t *Tokens) response(c *structs.CurrentToken, grant *structs.Grant, targetName string) *structs.TokenResponse {
	now := t.now()
	return &structs.TokenResponse{
		Token:       c.Token,
		TokenType:   constants.TokenTypeBearer,
		Target:      targetName,
		Scopes:      scopesOrEmpty(grant.Scopes),
		IssuedAt:    c.IssuedAt,
		ExpiresAt:   c.ExpiresAt,
		ExpiresIn:   int64(c.ExpiresAt.Sub(now).Seconds()),
		RotateAfter: int64(c.IssuedAt.Add(grant.RotateAfter()).Sub(now).Seconds()),
	}
}
