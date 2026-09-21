package render

import (
	"github.com/gin-gonic/gin"

	"github.com/siddharth120604/rotating-s2s/pkg/constants"
)

func requestID(c *gin.Context) string {
	if v, ok := c.Get(constants.ContextRequestID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
