package v1

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"nodepass-hub/internal/api/response"
	hubpkg "nodepass-hub/internal/hub"
	cryptoutil "nodepass-hub/pkg/crypto"
)

type WSHandler struct {
	hub    *hubpkg.Hub
	secret string

	upgrader websocket.Upgrader
}

func NewWSHandler(h *hubpkg.Hub, secret string) *WSHandler {
	return &WSHandler{
		hub:    h,
		secret: strings.TrimSpace(secret),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			CheckOrigin: func(_ *http.Request) bool {
				return true
			},
		},
	}
}

func RegisterWSRoutes(router gin.IRoutes, h *hubpkg.Hub, secret string) {
	handler := NewWSHandler(h, secret)
	router.GET("/ws/agent", handler.Agent)
}

// Agent
// @Summary Agent
// @Description Auto-generated endpoint documentation for Agent.
// @Tags websocket
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /ws/agent [get]
func (h *WSHandler) Agent(c *gin.Context) {
	if h.hub == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "hub unavailable")
		return
	}

	agentID := strings.TrimSpace(c.Query("agent_id"))
	token := strings.TrimSpace(c.Query("token"))
	if agentID == "" || token == "" {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	if !cryptoutil.VerifyAgentHMACToken(agentID, token, h.secret) {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	client := hubpkg.NewAgentClient(agentID, conn, h.hub)
	h.hub.Register(client)
	client.Start()
}
