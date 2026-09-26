package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/controller/render"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type sessionResolver interface {
	Resolve(ctx context.Context, rawCookie string) (*structs.User, error)
}

// Session authenticates a human operator from the session cookie.
func Session(auth sessionResolver, redirectToLogin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie(constants.SessionCookie)
		if err != nil || cookie == "" {
			denySession(c, redirectToLogin)
			return
		}

		user, err := auth.Resolve(c.Request.Context(), cookie)
		if err != nil {
			denySession(c, redirectToLogin)
			return
		}

		c.Set(constants.ContextUser, user)
		c.Set(constants.ContextActor, structs.Actor{
			Type: constants.ActorUser,
			ID:   user.Email,
		})
		c.Next()
	}
}

// RequireMutate gates the destructive controls.
func RequireMutate() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := UserFrom(c)
		if !ok || !user.CanMutate() {
			render.Error(c, apperr.Forbidden.WithMessage(
				"your role (%s) cannot perform this action", roleOf(user)))
			c.Abort()
			return
		}
		c.Next()
	}
}

func denySession(c *gin.Context, redirect bool) {
	if redirect {
		c.Redirect(http.StatusSeeOther, "/login")
	} else {
		render.Error(c, apperr.Unauthorized.WithMessage("sign in to continue"))
	}
	c.Abort()
}

func roleOf(u *structs.User) string {
	if u == nil {
		return "anonymous"
	}
	return string(u.Role)
}
