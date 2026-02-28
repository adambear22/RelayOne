package middleware

import (
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"nodepass-hub/internal/api/response"
	jwtutil "nodepass-hub/pkg/jwt"
)

const apiKeyContextKey = "api_key"

type APIKeyPrincipal struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

func APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := strings.TrimSpace(c.GetHeader("X-API-Key"))
		principal, ok := validateAPIKey(apiKey)
		if !ok {
			response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
			c.Abort()
			return
		}

		c.Set(apiKeyContextKey, principal)
		c.Next()
	}
}

func RequireAPIKeyScope(scope string) gin.HandlerFunc {
	required := strings.TrimSpace(scope)
	return func(c *gin.Context) {
		if required == "" {
			c.Next()
			return
		}

		principal, ok := GetAPIKeyPrincipal(c)
		if !ok {
			response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
			c.Abort()
			return
		}

		if !apiKeyHasScope(principal.Scopes, required) {
			response.Fail(c, 403, response.ErrForbidden, "forbidden")
			c.Abort()
			return
		}

		c.Next()
	}
}

func AdminOrAPIKeyAuth(requiredScopes ...string) gin.HandlerFunc {
	scopes := make([]string, 0, len(requiredScopes))
	for _, scope := range requiredScopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}

	return func(c *gin.Context) {
		if rawAPIKey := strings.TrimSpace(c.GetHeader("X-API-Key")); rawAPIKey != "" {
			principal, ok := validateAPIKey(rawAPIKey)
			if !ok {
				response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
				c.Abort()
				return
			}

			for _, required := range scopes {
				if !apiKeyHasScope(principal.Scopes, required) {
					response.Fail(c, 403, response.ErrForbidden, "forbidden")
					c.Abort()
					return
				}
			}

			c.Set(apiKeyContextKey, principal)
			c.Next()
			return
		}

		tokenString := tokenFromRequest(c)
		if tokenString == "" {
			response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
			c.Abort()
			return
		}

		publicKey, err := loadRSAPublicKey()
		if err != nil {
			response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
			c.Abort()
			return
		}

		claims, err := jwtutil.ParseAccessToken(tokenString, publicKey)
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				response.Fail(c, 401, response.ErrTokenExpired, "token expired")
			} else {
				response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
			}
			c.Abort()
			return
		}

		if !strings.EqualFold(claims.Role, "admin") {
			response.Fail(c, 403, response.ErrForbidden, "forbidden")
			c.Abort()
			return
		}

		c.Set(claimsContextKey, claims)
		c.Next()
	}
}

func GetAPIKeyPrincipal(c *gin.Context) (*APIKeyPrincipal, bool) {
	value, ok := c.Get(apiKeyContextKey)
	if !ok {
		return nil, false
	}

	principal, ok := value.(*APIKeyPrincipal)
	if !ok || principal == nil {
		return nil, false
	}

	copied := &APIKeyPrincipal{Name: principal.Name}
	if len(principal.Scopes) > 0 {
		copied.Scopes = append([]string(nil), principal.Scopes...)
	}
	return copied, true
}

func validateAPIKey(rawAPIKey string) (*APIKeyPrincipal, bool) {
	provided := strings.TrimSpace(rawAPIKey)
	if provided == "" {
		return nil, false
	}

	cfg := GetSystemConfigCache()
	if cfg == nil || len(cfg.ExternalAPIKeys) == 0 {
		return nil, false
	}

	for _, item := range cfg.ExternalAPIKeys {
		candidate := strings.TrimSpace(item.Key)
		if candidate == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(candidate)) != 1 {
			continue
		}

		scopes := make([]string, 0, len(item.Scopes))
		for _, scope := range item.Scopes {
			trimmed := strings.TrimSpace(scope)
			if trimmed != "" {
				scopes = append(scopes, trimmed)
			}
		}

		return &APIKeyPrincipal{
			Name:   strings.TrimSpace(item.Name),
			Scopes: scopes,
		}, true
	}

	return nil, false
}

func apiKeyHasScope(scopes []string, required string) bool {
	requested := strings.TrimSpace(required)
	if requested == "" {
		return true
	}
	if len(scopes) == 0 {
		return true
	}

	for _, scope := range scopes {
		value := strings.TrimSpace(scope)
		if value == "" {
			continue
		}
		if value == "*" || strings.EqualFold(value, requested) {
			return true
		}
		if strings.HasSuffix(value, ".*") {
			prefix := strings.TrimSuffix(strings.ToLower(value), "*")
			if strings.HasPrefix(strings.ToLower(requested), prefix) {
				return true
			}
		}
	}

	return false
}
