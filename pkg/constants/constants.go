// Package constants holds every fixed value in the system.
package constants

import "time"

type ServiceStatus string

const (
	ServiceActive   ServiceStatus = "active"
	ServiceDisabled ServiceStatus = "disabled"
)

type GrantStatus string

const (
	GrantActive  GrantStatus = "active"
	GrantRevoked GrantStatus = "revoked"
)

type UserRole string

const (
	RoleAdmin    UserRole = "admin"
	RoleOperator UserRole = "operator"
	RoleViewer   UserRole = "viewer"
)

type ActorType string

const (
	ActorService ActorType = "service"
	ActorUser    ActorType = "user"
	ActorSystem  ActorType = "system"
)

const (
	ActionUserLogin           = "user.login"
	ActionUserLogout          = "user.logout"
	ActionServiceCreate       = "service.create"
	ActionServiceUpdate       = "service.update"
	ActionServiceRotateSecret = "service.rotate_secret"
	ActionGrantCreate         = "grant.create"
	ActionGrantUpdate         = "grant.update"
	ActionGrantRevoke         = "grant.revoke"
	ActionGrantRotate         = "grant.rotate"
	ActionTokenIssue          = "token.issue"
	ActionTokenRevoke         = "token.revoke"
)

// Audit target types.
const (
	TargetUser    = "user"
	TargetService = "service"
	TargetGrant   = "grant"
	TargetToken   = "token"
)

const (
	TokenPrefix = "s2s_"

	ClientSecretPrefix = "s2ssec_"

	TokenEntropyBytes = 32
)

const (
	ReasonNotFound        = "not_found"
	ReasonExpired         = "expired"
	ReasonRevoked         = "revoked"
	ReasonGrantRevoked    = "grant_revoked"
	ReasonWrongTarget     = "wrong_target"
	ReasonServiceDisabled = "service_disabled"
)

// TokenTypeBearer is the token_type returned at issuance.
const TokenTypeBearer = "Bearer"

const (
	MySQLErrDupEntry        = 1062
	MySQLErrCheckConstraint = 3819
)

// Index names, used to tell one unique-constraint violation from another.
const (
	IdxServiceName  = "uk_services_name"
	IdxGrantPair    = "uk_grants_pair"
	IdxTokenHash    = "uk_tokens_hash"
	IdxTokenCurrent = "uk_tokens_current"
)

const (
	RedisKeyToken        = "tok:"
	RedisKeyCurrentToken = "grant:cur:"
	RedisKeyNegative     = "neg:"
	RedisKeyService      = "svc:"
	RedisKeyStats        = "stat:"
)

const (
	ContextRequestID = "request_id"
	ContextActor     = "actor"

	ContextCaller = "caller"

	ContextUser = "user"

	SessionCookie   = "s2s_session"
	SessionLifetime = 12 * time.Hour

	HeaderRequestID     = "X-Request-ID"
	HeaderAuthorization = "Authorization"
	BearerPrefix        = "Bearer "
)

const (
	DefaultPageLimit = 50
	MaxPageLimit     = 200

	MinPasswordLen    = 12
	MinServiceNameLen = 2
	MaxServiceNameLen = 128

	MinTokenLifetime = time.Minute
)

const (
	StatsBucketTTL = 10 * time.Minute

	StatsFlushInterval = time.Minute

	GraphWindow = time.Hour
)

const (
	InvalidationAttempts = 3
	InvalidationBackoff  = 50 * time.Millisecond
)

// SecretWarning is shown once, at the only moment a plaintext secret exists outside
// the owning service's own config.
const SecretWarning = "Store this secret now: it is hashed with argon2id and cannot be retrieved again. " +
	"Put it in one Kubernetes Secret mounted by every pod of this service."

// DummyArgon2Hash is a real hash of a random value.
const DummyArgon2Hash = `$argon2id$v=19$m=65536,t=3,p=4$` +
	`ZHVtbXlzYWx0ZHVtbXlzYQ$3b7ZQ0Wd3vLp5qXhK8sN2mYtRfGcUvBnJwEaScDxTiM`
