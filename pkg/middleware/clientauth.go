package middleware

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/controller/render"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type authenticator interface {
	Authenticate(ctx context.Context, clientID, secret string) (*structs.Service, error)
}

// ClientCredentials authenticates a machine caller from HTTP Basic, with client_id
// as the username and client_secret as the password.
func ClientCredentials(auth authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientID, secret, ok := c.Request.BasicAuth()
		if !ok || clientID == "" || secret == "" {

			c.Header("WWW-Authenticate", `Basic realm="s2s", error="invalid_client"`)
			render.Error(c, apperr.InvalidClient.WithMessage(
				"client credentials required via HTTP Basic (client_id:client_secret)"))
			c.Abort()
			return
		}

		svc, err := auth.Authenticate(c.Request.Context(), clientID, secret)
		if err != nil {
			c.Header("WWW-Authenticate", `Basic realm="s2s", error="invalid_client"`)
			render.Error(c, err)
			c.Abort()
			return
		}

		c.Set(constants.ContextCaller, svc)

		c.Set(constants.ContextActor, structs.Actor{
			Type: constants.ActorService,
			ID:   svc.Name,
		})
		c.Next()
	}
}
