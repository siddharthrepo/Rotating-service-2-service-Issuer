// Package structs holds every data struct in the system: domain rows, wire DTOs,
// configuration, filters, and service inputs.
package structs

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/siddharth120604/rotating-s2s/pkg/constants"
)

// ScopeList maps a MySQL JSON column to []string.
type ScopeList []string

func (s ScopeList) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]string(s))
	if err != nil {
		return nil, fmt.Errorf("marshal scopes: %w", err)
	}
	return string(b), nil
}

func (s *ScopeList) Scan(src any) error {
	b, err := jsonBytes(src, "scopes")
	if err != nil {
		return err
	}
	if b == nil {
		*s = nil
		return nil
	}
	return json.Unmarshal(b, (*[]string)(s))
}

// Contains reports whether the granted scopes cover the one being asked for.
func (s ScopeList) Contains(scope string) bool {
	for _, got := range s {
		if got == scope {
			return true
		}
	}
	return false
}

// JSONMap backs free-form metadata columns.
type JSONMap map[string]any

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(map[string]any(m))
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return string(b), nil
}

func (m *JSONMap) Scan(src any) error {
	b, err := jsonBytes(src, "metadata")
	if err != nil {
		return err
	}
	if b == nil {
		*m = nil
		return nil
	}
	return json.Unmarshal(b, (*map[string]any)(m))
}

// Service is one registered service identity.
type Service struct {
	ID               uint64                  `db:"id"`
	Name             string                  `db:"name"`
	ClientID         string                  `db:"client_id"`
	ClientSecretHash string                  `db:"client_secret_hash"`
	OwnerTeam        sql.NullString          `db:"owner_team"`
	Description      sql.NullString          `db:"description"`
	Status           constants.ServiceStatus `db:"status"`
	SecretRotatedAt  sql.NullTime            `db:"secret_rotated_at"`
	CreatedAt        time.Time               `db:"created_at"`
	UpdatedAt        time.Time               `db:"updated_at"`
}

func (s *Service) IsActive() bool { return s.Status == constants.ServiceActive }

// Grant is a (caller -> target) relationship.
type Grant struct {
	ID                 uint64                `db:"id"`
	CallerServiceID    uint64                `db:"caller_service_id"`
	TargetServiceID    uint64                `db:"target_service_id"`
	Scopes             ScopeList             `db:"scopes"`
	LifetimeSeconds    uint32                `db:"lifetime_seconds"`
	RotateAfterSeconds uint32                `db:"rotate_after_seconds"`
	Status             constants.GrantStatus `db:"status"`
	RevokedAt          sql.NullTime          `db:"revoked_at"`
	RevokedReason      sql.NullString        `db:"revoked_reason"`
	CreatedAt          time.Time             `db:"created_at"`
	UpdatedAt          time.Time             `db:"updated_at"`
}

func (g *Grant) IsActive() bool          { return g.Status == constants.GrantActive }
func (g *Grant) Lifetime() time.Duration { return time.Duration(g.LifetimeSeconds) * time.Second }
func (g *Grant) RotateAfter() time.Duration {
	return time.Duration(g.RotateAfterSeconds) * time.Second
}

// Overlap is how long a superseded token stays usable after its replacement has
// been issued.
func (g *Grant) Overlap() time.Duration { return g.Lifetime() - g.RotateAfter() }

// GrantDetail is a grant with both endpoints resolved to names.
type GrantDetail struct {
	Grant
	CallerName string `db:"caller_name"`
	TargetName string `db:"target_name"`
}

// Token records an issuance.
type Token struct {
	ID           uint64       `db:"id"`
	JTI          string       `db:"jti"`
	GrantID      uint64       `db:"grant_id"`
	TokenHash    string       `db:"token_hash"`
	IssuedAt     time.Time    `db:"issued_at"`
	ExpiresAt    time.Time    `db:"expires_at"`
	RevokedAt    sql.NullTime `db:"revoked_at"`
	SupersededAt sql.NullTime `db:"superseded_at"`
	IssuedToIP   []byte       `db:"issued_to_ip"`
}

// IsCurrent reports whether this is the token handed to new callers.
func (t *Token) IsCurrent() bool { return !t.RevokedAt.Valid && !t.SupersededAt.Valid }

func (t *Token) IsValidAt(now time.Time) bool {
	return !t.RevokedAt.Valid && now.Before(t.ExpiresAt)
}

// Actor is who performed an audited action.
type Actor struct {
	Type constants.ActorType
	ID   string
}

func SystemActor() Actor { return Actor{Type: constants.ActorSystem, ID: "system"} }

type AuditEntry struct {
	ID         uint64              `db:"id"`
	ActorType  constants.ActorType `db:"actor_type"`
	ActorID    string              `db:"actor_id"`
	Action     string              `db:"action"`
	TargetType sql.NullString      `db:"target_type"`
	TargetID   sql.NullString      `db:"target_id"`
	Reason     sql.NullString      `db:"reason"`
	Metadata   JSONMap             `db:"metadata"`
	RequestIP  []byte              `db:"request_ip"`
	CreatedAt  time.Time           `db:"created_at"`
}

// TokenDetail is a token with everything needed to decide validity, resolved in one
// query: the grant it belongs to, both endpoints, and their statuses.
type TokenDetail struct {
	Token
	GrantStatus  constants.GrantStatus   `db:"grant_status"`
	Scopes       ScopeList               `db:"scopes"`
	CallerName   string                  `db:"caller_name"`
	CallerStatus constants.ServiceStatus `db:"caller_status"`
	TargetName   string                  `db:"target_name"`
	TargetStatus constants.ServiceStatus `db:"target_status"`
}

// ToCached flattens a row into the form that gets cached and validated.
func (t *TokenDetail) ToCached() *CachedToken {
	return &CachedToken{
		JTI:          t.JTI,
		GrantID:      t.GrantID,
		Caller:       t.CallerName,
		Target:       t.TargetName,
		Scopes:       []string(t.Scopes),
		IssuedAt:     t.IssuedAt,
		ExpiresAt:    t.ExpiresAt,
		Revoked:      t.RevokedAt.Valid,
		GrantActive:  t.GrantStatus == constants.GrantActive,
		CallerActive: t.CallerStatus == constants.ServiceActive,
		TargetActive: t.TargetStatus == constants.ServiceActive,
	}
}

// CachedToken is the flattened record stored in Redis: everything needed to decide
// validity without touching MySQL.
type CachedToken struct {
	NotFound bool `json:"nf,omitempty"`

	JTI          string    `json:"jti,omitempty"`
	GrantID      uint64    `json:"gid,omitempty"`
	Caller       string    `json:"cl,omitempty"`
	Target       string    `json:"tg,omitempty"`
	Scopes       []string  `json:"sc,omitempty"`
	IssuedAt     time.Time `json:"iat,omitempty"`
	ExpiresAt    time.Time `json:"exp,omitempty"`
	Revoked      bool      `json:"rv,omitempty"`
	GrantActive  bool      `json:"ga,omitempty"`
	CallerActive bool      `json:"ca,omitempty"`
	TargetActive bool      `json:"ta,omitempty"`
}

// Validate decides whether a presented token is usable by the service asking about
// it.
func (c *CachedToken) Validate(now time.Time, askingService string) (bool, string) {
	switch {
	case c.NotFound:
		return false, constants.ReasonNotFound
	case c.Revoked:
		return false, constants.ReasonRevoked
	case !c.GrantActive:
		return false, constants.ReasonGrantRevoked
	case !c.CallerActive, !c.TargetActive:
		return false, constants.ReasonServiceDisabled
	case !now.Before(c.ExpiresAt):
		return false, constants.ReasonExpired

	case c.Target != askingService:
		return false, constants.ReasonWrongTarget
	default:
		return true, ""
	}
}

// CachedAuth memoises a successful client-credential verification.
type CachedAuth struct {
	SecretSHA256 string `json:"sh"`
	ServiceID    uint64 `json:"id"`
	Name         string `json:"n"`
	ClientID     string `json:"cid"`
	Active       bool   `json:"a"`
}

// Service rebuilds the minimal identity the request path needs.
func (c *CachedAuth) ToService() *Service {
	status := constants.ServiceActive
	if !c.Active {
		status = constants.ServiceDisabled
	}
	return &Service{ID: c.ServiceID, Name: c.Name, ClientID: c.ClientID, Status: status}
}

// CurrentToken is the cached plaintext for a grant -- the only place a usable token
// exists outside the issuance response.
type CurrentToken struct {
	Token     string    `json:"t"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
}

// GrantStatBucket is one minute of call telemetry for one grant.
type GrantStatBucket struct {
	GrantID     uint64    `db:"grant_id"`
	BucketStart time.Time `db:"bucket_start"`
	CallCount   uint64    `db:"call_count"`
	DenyCount   uint64    `db:"deny_count"`
}

// GraphNode is a service in the dependency graph.
type GraphNode struct {
	ID        uint64 `json:"id"         db:"id"`
	Name      string `json:"name"       db:"name"`
	OwnerTeam string `json:"owner_team,omitempty" db:"owner_team"`
	Status    string `json:"status"     db:"status"`

	InDegree  int `json:"in_degree"  db:"in_degree"`
	OutDegree int `json:"out_degree" db:"out_degree"`
}

// GraphEdge is a grant, enriched with how much it is actually used.
type GraphEdge struct {
	GrantID uint64 `json:"grant_id" db:"grant_id"`
	Caller  string `json:"caller"   db:"caller"`
	Target  string `json:"target"   db:"target"`
	Status  string `json:"status"   db:"status"`

	Scopes   []string   `json:"scopes"    db:"-"`
	Calls    uint64     `json:"calls"     db:"calls"`
	Denies   uint64     `json:"denies"    db:"denies"`
	LastSeen *time.Time `json:"last_seen,omitempty" db:"last_seen"`
}

type Graph struct {
	Nodes      []GraphNode `json:"nodes"`
	Edges      []GraphEdge `json:"edges"`
	WindowSecs int         `json:"window_seconds"`
}

// User is a human operator.
type User struct {
	ID           uint64                  `db:"id"`
	Email        string                  `db:"email"`
	Name         string                  `db:"name"`
	PasswordHash string                  `db:"password_hash"`
	Role         constants.UserRole      `db:"role"`
	Status       constants.ServiceStatus `db:"status"`
	CreatedAt    time.Time               `db:"created_at"`
}

func (u *User) IsActive() bool { return u.Status == constants.ServiceActive }

// CanMutate reports whether this role may revoke, rotate, or register.
func (u *User) CanMutate() bool {
	return u.Role == constants.RoleAdmin || u.Role == constants.RoleOperator
}

type Session struct {
	ID        string    `db:"id"`
	UserID    uint64    `db:"user_id"`
	ExpiresAt time.Time `db:"expires_at"`
	CreatedAt time.Time `db:"created_at"`
}

type LoginRequest struct {
	Email    string `json:"email" form:"email" binding:"required"`
	Password string `json:"password" form:"password" binding:"required"`
}

type Config struct {
	Server    Server    `mapstructure:"server"`
	MySQL     MySQL     `mapstructure:"mysql"`
	Redis     Redis     `mapstructure:"redis"`
	Cache     Cache     `mapstructure:"cache"`
	Tokens    Tokens    `mapstructure:"tokens"`
	RateLimit RateLimit `mapstructure:"ratelimit"`
	Security  Security  `mapstructure:"security"`
	Log       Log       `mapstructure:"log"`
}

type Server struct {
	Addr          string        `mapstructure:"addr"`
	OpsAddr       string        `mapstructure:"ops_addr"`
	ReadTimeout   time.Duration `mapstructure:"read_timeout"`
	WriteTimeout  time.Duration `mapstructure:"write_timeout"`
	ShutdownGrace time.Duration `mapstructure:"shutdown_grace"`

	AdminAPIKey string `mapstructure:"admin_api_key"`

	SecureCookies bool `mapstructure:"secure_cookies"`
}

type MySQL struct {
	DSN             string        `mapstructure:"dsn"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

type Redis struct {
	Enabled     bool          `mapstructure:"enabled"`
	Addr        string        `mapstructure:"addr"`
	Password    string        `mapstructure:"password"`
	DB          int           `mapstructure:"db"`
	PoolSize    int           `mapstructure:"pool_size"`
	DialTimeout time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout time.Duration `mapstructure:"read_timeout"`
}

// Cache has no in-process tier.
type Cache struct {
	NegativeTTL time.Duration `mapstructure:"negative_ttl"`
	ServiceTTL  time.Duration `mapstructure:"service_ttl"`
}

type Tokens struct {
	DefaultLifetime    time.Duration `mapstructure:"default_lifetime"`
	DefaultRotateAfter time.Duration `mapstructure:"default_rotate_after"`

	MaxLifetime time.Duration `mapstructure:"max_lifetime"`
}

// RateLimit caps per client_id.
type RateLimit struct {
	IssuancePerMinute   int `mapstructure:"issuance_per_minute"`
	IntrospectPerMinute int `mapstructure:"introspect_per_minute"`
}

type Security struct {
	Argon2 Argon2Params `mapstructure:"argon2"`
}

// Argon2Params is used both as configuration and as the parameter set passed to the
// hashing functions.
type Argon2Params struct {
	MemoryKiB   uint32 `mapstructure:"memory_kib"`
	Iterations  uint32 `mapstructure:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism"`
	SaltLength  uint32 `mapstructure:"salt_length"`
	KeyLength   uint32 `mapstructure:"key_length"`
}

type Log struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`

	SampleInitial    int `mapstructure:"sample_initial"`
	SampleThereafter int `mapstructure:"sample_thereafter"`
}

type CreateServiceInput struct {
	Name        string
	OwnerTeam   string
	Description string
	Actor       Actor
	RemoteIP    string
}

type CreateGrantInput struct {
	CallerName  string
	TargetName  string
	Scopes      []string
	Lifetime    time.Duration
	RotateAfter time.Duration
	Actor       Actor
	RemoteIP    string
}

type UpdateGrantInput struct {
	ID          uint64
	Scopes      []string
	Lifetime    time.Duration
	RotateAfter time.Duration
	Actor       Actor
}

// Credentials carries the one and only time a plaintext secret exists outside the
// owning service's config.
type Credentials struct {
	Service      *Service
	ClientID     string
	ClientSecret string
}

type ServiceFilter struct {
	OwnerTeam string
	Status    string
	Limit     int
	Offset    int
}

type GrantFilter struct {
	CallerID uint64
	TargetID uint64
	Status   string
	Limit    int
	Offset   int
}

type AuditFilter struct {
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Limit      int
	Offset     int
}

type IssueTokenRequest struct {
	Target string `json:"target" binding:"required"`
}

type IntrospectRequest struct {
	Token string `json:"token" binding:"required"`
}

type CreateServiceRequest struct {
	Name        string `json:"name" binding:"required"`
	OwnerTeam   string `json:"owner_team"`
	Description string `json:"description"`
}

type UpdateServiceStatusRequest struct {
	Status string `json:"status" binding:"required"`
}

type CreateGrantRequest struct {
	Caller      string   `json:"caller" binding:"required"`
	Target      string   `json:"target" binding:"required"`
	Scopes      []string `json:"scopes"`
	Lifetime    string   `json:"lifetime"`
	RotateAfter string   `json:"rotate_after"`
}

type UpdateGrantRequest struct {
	Scopes      []string `json:"scopes"`
	Lifetime    string   `json:"lifetime"`
	RotateAfter string   `json:"rotate_after"`
}

type ServiceResponse struct {
	ID              uint64     `json:"id"`
	Name            string     `json:"name"`
	ClientID        string     `json:"client_id"`
	OwnerTeam       string     `json:"owner_team,omitempty"`
	Description     string     `json:"description,omitempty"`
	Status          string     `json:"status"`
	SecretRotatedAt *time.Time `json:"secret_rotated_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// CredentialsResponse is the only place a plaintext secret is ever emitted.
type CredentialsResponse struct {
	ServiceResponse
	ClientSecret string `json:"client_secret"`
	Warning      string `json:"warning"`
}

type GrantResponse struct {
	ID          uint64   `json:"id"`
	Caller      string   `json:"caller"`
	Target      string   `json:"target"`
	Scopes      []string `json:"scopes"`
	Lifetime    string   `json:"lifetime"`
	RotateAfter string   `json:"rotate_after"`

	Overlap       string    `json:"overlap"`
	Status        string    `json:"status"`
	RevokedReason string    `json:"revoked_reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type AuditResponse struct {
	ID         uint64    `json:"id"`
	ActorType  string    `json:"actor_type"`
	ActorID    string    `json:"actor_id"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type,omitempty"`
	TargetID   string    `json:"target_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Metadata   JSONMap   `json:"metadata,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// TokenResponse is returned by POST /v1/token.
type TokenResponse struct {
	Token       string    `json:"token"`
	TokenType   string    `json:"token_type"`
	Target      string    `json:"target"`
	Scopes      []string  `json:"scopes"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ExpiresIn   int64     `json:"expires_in"`
	RotateAfter int64     `json:"rotate_after"`
}

// IntrospectResponse always comes back with HTTP 200, even for an invalid token.
type IntrospectResponse struct {
	Active    bool       `json:"active"`
	Reason    string     `json:"reason,omitempty"`
	Caller    string     `json:"caller,omitempty"`
	Target    string     `json:"target,omitempty"`
	Scopes    []string   `json:"scopes,omitempty"`
	JTI       string     `json:"jti,omitempty"`
	IssuedAt  *time.Time `json:"issued_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// RevokeRequest carries the operator's reason, which is recorded in the audit
// trail.
type RevokeRequest struct {
	Reason string `json:"reason" binding:"required"`
}

type RevokeResponse struct {
	GrantID       uint64 `json:"grant_id"`
	Status        string `json:"status"`
	TokensRevoked int    `json:"tokens_revoked"`
	Reason        string `json:"reason"`
}

// RotateResponse deliberately does NOT include the new token.
type RotateResponse struct {
	GrantID       uint64    `json:"grant_id"`
	Status        string    `json:"status"`
	TokensRevoked int       `json:"tokens_revoked"`
	NewTokenJTI   string    `json:"new_token_jti"`
	ExpiresAt     time.Time `json:"expires_at"`
	Reason        string    `json:"reason"`
}

type ListResponse struct {
	Items any `json:"items"`
	Count int `json:"count"`
}

type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

type HealthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}
