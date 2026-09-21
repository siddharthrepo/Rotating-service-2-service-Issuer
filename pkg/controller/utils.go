package controller

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/siddharth120604/rotating-s2s/pkg/apperr"
	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/controller/render"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

func pathUint(c *gin.Context, name string) (uint64, error) {
	raw := c.Param(name)
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		return 0, apperr.BadRequest.WithMessage("%s must be a positive integer, got %q", name, raw)
	}
	return id, nil
}

func queryInt(c *gin.Context, name string, fallback int) int {
	raw := c.Query(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return fallback
	}
	return v
}

func parseDuration(raw, field string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.BadRequest.WithMessage(
			"%s must be a Go duration such as \"45m\" or \"1h30m\", got %q", field, raw)
	}
	if d <= 0 {
		return 0, apperr.BadRequest.WithMessage("%s must be positive, got %q", field, raw)
	}
	return d, nil
}

func (a *Admin) revocationArgs(c *gin.Context) (uint64, string, bool) {
	id, err := pathUint(c, "id")
	if err != nil {
		render.Error(c, err)
		return 0, "", false
	}
	var req structs.RevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		render.Error(c, apperr.BadRequest.WithMessage(
			"a reason is required: %v", err))
		return 0, "", false
	}
	return id, req.Reason, true
}

func toServiceResponse(s *structs.Service) structs.ServiceResponse {
	r := structs.ServiceResponse{
		ID:          s.ID,
		Name:        s.Name,
		ClientID:    s.ClientID,
		OwnerTeam:   s.OwnerTeam.String,
		Description: s.Description.String,
		Status:      string(s.Status),
		CreatedAt:   s.CreatedAt,
	}
	if s.SecretRotatedAt.Valid {
		t := s.SecretRotatedAt.Time
		r.SecretRotatedAt = &t
	}
	return r
}

func toCredentialsResponse(c *structs.Credentials) structs.CredentialsResponse {
	return structs.CredentialsResponse{
		ServiceResponse: toServiceResponse(c.Service),
		ClientSecret:    c.ClientSecret,
		Warning:         constants.SecretWarning,
	}
}

func toGrantResponse(g *structs.GrantDetail) structs.GrantResponse {
	scopes := []string(g.Scopes)
	if scopes == nil {
		scopes = []string{}
	}
	return structs.GrantResponse{
		ID:            g.ID,
		Caller:        g.CallerName,
		Target:        g.TargetName,
		Scopes:        scopes,
		Lifetime:      g.Lifetime().String(),
		RotateAfter:   g.RotateAfter().String(),
		Overlap:       g.Overlap().String(),
		Status:        string(g.Status),
		RevokedReason: g.RevokedReason.String,
		CreatedAt:     g.CreatedAt,
	}
}

func toAuditResponse(e *structs.AuditEntry) structs.AuditResponse {
	return structs.AuditResponse{
		ID:         e.ID,
		ActorType:  string(e.ActorType),
		ActorID:    e.ActorID,
		Action:     e.Action,
		TargetType: e.TargetType.String,
		TargetID:   e.TargetID.String,
		Reason:     e.Reason.String,
		Metadata:   e.Metadata,
		CreatedAt:  e.CreatedAt,
	}
}

type serviceRow struct {
	structs.ServiceResponse
	InDegree  int
	OutDegree int
}

type grantRow struct {
	ID            uint64
	Caller        string
	Target        string
	Scopes        []string
	Lifetime      string
	RotateAfter   string
	Overlap       string
	Status        string
	RevokedReason string
	Calls         uint64
	CanMutate     bool
}

type auditRow struct {
	CreatedAt  string
	ActorType  string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Reason     string
	Detail     string
}

func servicesWithDegree(services []structs.Service, g *structs.Graph) []serviceRow {
	degree := make(map[string]structs.GraphNode, len(g.Nodes))
	for _, n := range g.Nodes {
		degree[n.Name] = n
	}
	out := make([]serviceRow, 0, len(services))
	for i := range services {
		r := serviceRow{ServiceResponse: toServiceResponse(&services[i])}
		if n, ok := degree[services[i].Name]; ok {
			r.InDegree, r.OutDegree = n.InDegree, n.OutDegree
		}
		out = append(out, r)
	}
	return out
}

func toGrantRow(g *structs.GrantDetail, calls map[uint64]uint64, user *structs.User) grantRow {
	resp := toGrantResponse(g)
	return grantRow{
		ID: resp.ID, Caller: resp.Caller, Target: resp.Target, Scopes: resp.Scopes,
		Lifetime: resp.Lifetime, RotateAfter: resp.RotateAfter, Overlap: resp.Overlap,
		Status: resp.Status, RevokedReason: resp.RevokedReason,
		Calls:     calls[resp.ID],
		CanMutate: user != nil && user.CanMutate(),
	}
}

func auditRows(entries []structs.AuditEntry) []auditRow {
	out := make([]auditRow, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		out = append(out, auditRow{
			CreatedAt:  e.CreatedAt.UTC().Format("2006-01-02 15:04:05"),
			ActorType:  string(e.ActorType),
			ActorID:    e.ActorID,
			Action:     e.Action,
			TargetType: e.TargetType.String,
			TargetID:   e.TargetID.String,
			Reason:     e.Reason.String,
			Detail:     summariseMetadata(e.Metadata),
		})
	}
	return out
}

func summariseMetadata(m structs.JSONMap) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for _, k := range []string{"caller", "target", "name", "status", "scopes",
		"lifetime", "rotate_after", "overlap", "tokens_revoked", "new_token_jti"} {
		if v, ok := m[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, "  ")
}
