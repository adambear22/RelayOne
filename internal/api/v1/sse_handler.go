package v1

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"nodepass-hub/internal/api/response"
	"nodepass-hub/internal/sse"
	jwtutil "nodepass-hub/pkg/jwt"
)

type SSEHandler struct {
	hub *sse.SSEHub
}

var (
	ssePublicKeyOnce sync.Once
	ssePublicKey     *rsa.PublicKey
	ssePublicKeyErr  error
)

func NewSSEHandler(hub *sse.SSEHub) *SSEHandler {
	return &SSEHandler{hub: hub}
}

func RegisterSSERoutes(group *gin.RouterGroup, hub *sse.SSEHub) {
	handler := NewSSEHandler(hub)
	group.GET("/events", handler.Events)
}

// Events
// @Summary Events
// @Description Auto-generated endpoint documentation for Events.
// @Tags sse
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/events [get]
func (h *SSEHandler) Events(c *gin.Context) {
	if h.hub == nil {
		response.Fail(c, 503, response.ErrInternal, "sse hub unavailable")
		return
	}

	tokenStr, err := extractAccessToken(c)
	if err != nil {
		response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
		return
	}

	publicKey, err := loadSSEPublicKey()
	if err != nil {
		response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
		return
	}

	claims, err := jwtutil.ParseAccessToken(tokenStr, publicKey)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			response.Fail(c, 401, response.ErrTokenExpired, "token expired")
			return
		}
		response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
		return
	}

	userID := strings.TrimSpace(claims.UserID)
	if userID == "" {
		response.Fail(c, 401, response.ErrUnauthorized, "unauthorized")
		return
	}

	flusher, ok := c.Writer.(interface{ Flush() })
	if !ok {
		response.Fail(c, 500, response.ErrInternal, "stream unsupported")
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")
	c.Header("Connection", "keep-alive")
	c.Status(200)

	client := sse.NewClient(userID, claims.Role)
	h.hub.Register(client)
	defer h.hub.Unregister(userID)

	lastID := c.GetHeader("Last-Event-ID")
	for _, event := range h.hub.Since(lastID) {
		if err := writeSSEEvent(c, event); err != nil {
			return
		}
		flusher.Flush()
	}

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-client.Done:
			return
		case event := <-client.Ch:
			if err := writeSSEEvent(c, event); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSEEvent(c *gin.Context, event sse.SSEEvent) error {
	if _, err := fmt.Fprintf(c.Writer, "id: %s\n", event.ID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.Writer, "event: %s\n", event.Type); err != nil {
		return err
	}

	for _, line := range strings.Split(event.Data, "\n") {
		if _, err := fmt.Fprintf(c.Writer, "data: %s\n", line); err != nil {
			return err
		}
	}

	_, err := fmt.Fprint(c.Writer, "\n")
	return err
}

func extractAccessToken(c *gin.Context) (string, error) {
	if token, err := c.Cookie("access_token"); err == nil {
		token = strings.TrimSpace(token)
		if token != "" {
			return token, nil
		}
	}
	if token, err := c.Cookie("token"); err == nil {
		token = strings.TrimSpace(token)
		if token != "" {
			return token, nil
		}
	}
	return "", errors.New("missing access token")
}

func loadSSEPublicKey() (*rsa.PublicKey, error) {
	ssePublicKeyOnce.Do(func() {
		pem := strings.TrimSpace(os.Getenv("NODEPASS_JWT_PUBLIC_KEY"))
		if pem == "" {
			path := strings.TrimSpace(os.Getenv("NODEPASS_JWT_PUBLIC_KEY_FILE"))
			if path != "" {
				buf, err := os.ReadFile(path)
				if err != nil {
					ssePublicKeyErr = err
					return
				}
				pem = string(buf)
			}
		}
		if pem == "" {
			ssePublicKeyErr = errors.New("jwt public key not configured")
			return
		}

		ssePublicKey, ssePublicKeyErr = jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	})

	return ssePublicKey, ssePublicKeyErr
}
