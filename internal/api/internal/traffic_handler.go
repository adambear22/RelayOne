package internalapi

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/response"
	"nodepass-hub/internal/service"
	cryptoutil "nodepass-hub/pkg/crypto"
)

type TrafficHandler struct {
	trafficService service.TrafficService
	secret         string
}

type batchTrafficRequest struct {
	AgentID string                  `json:"agent_id"`
	Records []service.TrafficRecord `json:"records" binding:"required"`
}

func NewTrafficHandler(trafficService service.TrafficService, secret string) *TrafficHandler {
	return &TrafficHandler{
		trafficService: trafficService,
		secret:         strings.TrimSpace(secret),
	}
}

func RegisterTrafficInternalRoutes(router gin.IRoutes, trafficService service.TrafficService, secret string) {
	handler := NewTrafficHandler(trafficService, secret)
	router.POST("/api/internal/traffic/report", handler.Report)
	router.POST("/api/internal/traffic/batch", handler.Batch)
}

func (h *TrafficHandler) Report(c *gin.Context) {
	if h.trafficService == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "service unavailable")
		return
	}

	agentID, ok := h.authorizeAgent(c)
	if !ok {
		return
	}

	var req service.TrafficRecord
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if err := h.trafficService.HandleReport(c.Request.Context(), agentID, []service.TrafficRecord{req}); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "handle traffic report failed")
		return
	}

	response.Success(c, gin.H{"ok": true})
}

func (h *TrafficHandler) Batch(c *gin.Context) {
	if h.trafficService == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "service unavailable")
		return
	}

	agentID, ok := h.authorizeAgent(c)
	if !ok {
		return
	}

	var req batchTrafficRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Records) == 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}
	if strings.TrimSpace(req.AgentID) != "" {
		agentID = strings.TrimSpace(req.AgentID)
	}

	if err := h.trafficService.HandleReport(c.Request.Context(), agentID, req.Records); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "handle traffic report failed")
		return
	}

	response.Success(c, gin.H{"ok": true})
}

func (h *TrafficHandler) authorizeAgent(c *gin.Context) (string, bool) {
	agentID := strings.TrimSpace(c.GetHeader("X-Agent-ID"))
	agentToken := strings.TrimSpace(c.GetHeader("X-Agent-Token"))
	if agentID == "" || agentToken == "" {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return "", false
	}

	if !cryptoutil.VerifyAgentHMACToken(agentID, agentToken, h.secret) {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return "", false
	}

	return agentID, true
}
