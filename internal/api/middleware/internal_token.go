package middleware

import (
	"crypto/subtle"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/response"
)

func InternalTokenAuth(token string) gin.HandlerFunc {
	expected := strings.TrimSpace(token)

	return func(c *gin.Context) {
		if isLoopbackClient(c.ClientIP()) {
			c.Next()
			return
		}

		provided := strings.TrimSpace(c.GetHeader("X-Internal-Token"))
		if provided == "" {
			provided = strings.TrimSpace(c.Query("internal_token"))
		}
		if provided == "" {
			provided = bearerTokenFromRequest(c.GetHeader("Authorization"))
		}

		if expected == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
			c.Abort()
			return
		}

		c.Next()
	}
}

func bearerTokenFromRequest(header string) string {
	auth := strings.TrimSpace(header)
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(auth[7:])
}

func isLoopbackClient(clientIP string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}
