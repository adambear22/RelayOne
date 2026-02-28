package internalapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	inputsanitize "nodepass-hub/internal/api/sanitize"
	"nodepass-hub/internal/service"
	cryptoutil "nodepass-hub/pkg/crypto"
)

type DeployHandler struct {
	nodeService *service.NodeService
	secret      string
}

func NewDeployHandler(nodeService *service.NodeService, secret string) *DeployHandler {
	return &DeployHandler{nodeService: nodeService, secret: strings.TrimSpace(secret)}
}

func RegisterDeployInternalRoutes(router gin.IRoutes, nodeService *service.NodeService, secret string) {
	handler := NewDeployHandler(nodeService, secret)
	router.POST("/api/internal/deploy/progress", middleware.RateLimitByHeader("X-Agent-ID", 60, time.Minute), handler.Progress)
}

func (h *DeployHandler) Progress(c *gin.Context) {
	if h.nodeService == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "service unavailable")
		return
	}

	agentID := strings.TrimSpace(c.GetHeader("X-Agent-ID"))
	agentToken := strings.TrimSpace(c.GetHeader("X-Agent-Token"))
	if agentID == "" || agentToken == "" {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	if !cryptoutil.VerifyAgentHMACToken(agentID, agentToken, h.secret) {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req service.DeployProgressPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if req.AgentID == "" {
		req.AgentID = agentID
	}
	req.AgentID = inputsanitize.Text(req.AgentID)
	req.Step = inputsanitize.Text(req.Step)
	req.Message = inputsanitize.Text(req.Message)

	if err := h.nodeService.HandleDeployProgress(c.Request.Context(), agentID, req); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "handle deploy progress failed")
		return
	}

	if strings.EqualFold(strings.TrimSpace(req.Step), "connected") {
		_ = h.nodeService.UpdateStatus(c.Request.Context(), agentID, "online")
	}

	response.Success(c, gin.H{"ok": true})
}
