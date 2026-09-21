package service

import (
	"context"
	"time"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

func entry(actor structs.Actor, action, targetType, targetID string) *structs.AuditEntry {
	return &structs.AuditEntry{
		ActorType:  actor.Type,
		ActorID:    actor.ID,
		Action:     action,
		TargetType: structs.NewNullString(targetType),
		TargetID:   structs.NewNullString(targetID),
	}
}

// RateLimiter caps requests per authenticated client.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, now time.Time) (bool, error)
}

func retry(ctx context.Context, attempts int, backoff time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff * time.Duration(i+1)):
		}
	}
	return err
}

func scopesOrEmpty(s structs.ScopeList) []string {
	if s == nil {
		return []string{}
	}
	return []string(s)
}

func validateServiceName(name string) error {
	if len(name) < constants.MinServiceNameLen || len(name) > constants.MaxServiceNameLen {
		return apperr.BadRequest.WithMessage("service name must be %d-%d characters",
			constants.MinServiceNameLen, constants.MaxServiceNameLen)
	}
	for _, c := range name {
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLower && !isDigit && c != '-' && c != '_' {
			return apperr.BadRequest.WithMessage(
				"service name must contain only lowercase letters, digits, '-' and '_'")
		}
	}
	return nil
}

func resolveTiming(policy structs.Tokens, lifetime, rotateAfter time.Duration) (time.Duration, time.Duration, error) {
	if lifetime == 0 {
		lifetime = policy.DefaultLifetime
	}
	if rotateAfter == 0 {
		rotateAfter = policy.DefaultRotateAfter
	}
	if lifetime < constants.MinTokenLifetime {
		return 0, 0, apperr.BadRequest.WithMessage("lifetime must be at least %s", constants.MinTokenLifetime)
	}
	if lifetime > policy.MaxLifetime {
		return 0, 0, apperr.LifetimeTooLong.WithMessage(
			"lifetime %s exceeds the maximum of %s", lifetime, policy.MaxLifetime)
	}
	if rotateAfter >= lifetime {
		return 0, 0, apperr.InvalidRotation.WithMessage(
			"rotate_after (%s) must be less than lifetime (%s); their difference is the overlap window",
			rotateAfter, lifetime)
	}
	return lifetime, rotateAfter, nil
}
