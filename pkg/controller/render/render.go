// Package render is the single place an HTTP response is shaped, so every endpoint
// returns the same envelope and no handler invents its own.
package render

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

// Error renders any error as the documented envelope.
func Error(c *gin.Context, err error) {
	e := apperr.As(err)
	c.JSON(e.Status, structs.ErrorEnvelope{Error: structs.ErrorBody{
		Code:      e.Code,
		Message:   e.Message,
		RequestID: requestID(c),
	}})
}

func OK(c *gin.Context, body any)      { c.JSON(http.StatusOK, body) }
func Created(c *gin.Context, body any) { c.JSON(http.StatusCreated, body) }
func NoContent(c *gin.Context)         { c.Status(http.StatusNoContent) }

// List wraps a slice with its count, so clients get a stable envelope even when the
// slice is empty.
func List(c *gin.Context, items any, count int) {
	c.JSON(http.StatusOK, structs.ListResponse{Items: items, Count: count})
}
