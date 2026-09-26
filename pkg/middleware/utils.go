package middleware

import (
	"crypto/subtle"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

// RequestIDFrom returns the id assigned by the RequestID middleware.
func RequestIDFrom(c *gin.Context) string {
	if v, ok := c.Get(constants.ContextRequestID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ActorFrom returns who is performing the request, for audit rows.
func ActorFrom(c *gin.Context) structs.Actor {
	if v, ok := c.Get(constants.ContextActor); ok {
		if a, ok := v.(structs.Actor); ok {
			return a
		}
	}
	return structs.SystemActor()
}

// CallerFrom returns the machine identity established by ClientCredentials.
func CallerFrom(c *gin.Context) (*structs.Service, bool) {
	v, ok := c.Get(constants.ContextCaller)
	if !ok {
		return nil, false
	}
	svc, ok := v.(*structs.Service)
	return svc, ok
}

// BearerToken extracts a presented s2s token from the Authorization header.
func BearerToken(c *gin.Context) (string, bool) { return bearerToken(c) }

// UserFrom returns the operator behind a dashboard session.
func UserFrom(c *gin.Context) (*structs.User, bool) {
	v, ok := c.Get(constants.ContextUser)
	if !ok {
		return nil, false
	}
	u, ok := v.(*structs.User)
	return u, ok
}

func bearerToken(c *gin.Context) (string, bool) {
	h := c.GetHeader(constants.HeaderAuthorization)
	if !strings.HasPrefix(h, constants.BearerPrefix) {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, constants.BearerPrefix))
	return tok, tok != ""
}

func secureEqual(a, b string) bool {
	if len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
