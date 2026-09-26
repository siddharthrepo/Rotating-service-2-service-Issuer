package render

import (
	"github.com/gin-gonic/gin"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
)

func requestID(c *gin.Context) string {
	if v, ok := c.Get(constants.ContextRequestID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
