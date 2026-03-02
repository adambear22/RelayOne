package middleware

import (
	"crypto/rsa"
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"nodepass-hub/internal/api/response"
	jwtutil "nodepass-hub/pkg/jwt"
)

const claimsContextKey = "claims"

type Claims = jwtutil.Claims

var (
	jwtPublicKeyOnce sync.Once
	jwtPublicKey     *rsa.PublicKey
	jwtPublicKeyErr  error
)

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if claims, ok := GetClaims(c); ok && claims != nil {
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

		c.Set(claimsContextKey, claims)
		c.Next()
	}
}

func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(roles) == 0 {
			c.Next()
			return
		}

		claims, ok := GetClaims(c)
		if !ok {
			response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
			c.Abort()
			return
		}

		for _, role := range roles {
			if strings.EqualFold(claims.Role, role) {
				c.Next()
				return
			}
		}

		response.Fail(c, 403, response.ErrForbidden, "forbidden")
		c.Abort()
	}
}

func RequirePermission(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := GetClaims(c)
		if !ok {
			response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
			c.Abort()
			return
		}

		for _, p := range claims.Permissions {
			if p == perm {
				c.Next()
				return
			}
		}

		response.Fail(c, 403, response.ErrForbidden, "forbidden")
		c.Abort()
	}
}

func GetClaims(c *gin.Context) (*Claims, bool) {
	val, ok := c.Get(claimsContextKey)
	if !ok {
		return nil, false
	}
	claims, ok := val.(*Claims)
	if !ok || claims == nil {
		return nil, false
	}
	return claims, true
}

func tokenFromRequest(c *gin.Context) string {
	if cookieToken, err := c.Cookie("access_token"); err == nil && cookieToken != "" {
		return cookieToken
	}
	if cookieToken, err := c.Cookie("token"); err == nil && cookieToken != "" {
		return cookieToken
	}

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}
	if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(authHeader[7:])
}

func loadRSAPublicKey() (*rsa.PublicKey, error) {
	jwtPublicKeyOnce.Do(func() {
		pem := strings.TrimSpace(os.Getenv("NODEPASS_JWT_PUBLIC_KEY"))
		if pem == "" {
			path := strings.TrimSpace(os.Getenv("NODEPASS_JWT_PUBLIC_KEY_FILE"))
			if path != "" {
				// #nosec G304,G703 -- path is provided by operator environment variable.
				buf, err := os.ReadFile(path)
				if err != nil {
					jwtPublicKeyErr = err
					return
				}
				pem = string(buf)
			}
		}
		if pem == "" {
			jwtPublicKeyErr = errors.New("jwt public key not configured")
			return
		}

		jwtPublicKey, jwtPublicKeyErr = jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	})

	return jwtPublicKey, jwtPublicKeyErr
}
