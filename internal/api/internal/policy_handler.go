package internalapi

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	"nodepass-hub/internal/service"
)

type PolicyHandler struct {
	policyService *service.PolicyService
}

type enforcePolicyRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Policy string `json:"policy" binding:"required"`
}

func NewPolicyHandler(policyService *service.PolicyService) *PolicyHandler {
	return &PolicyHandler{policyService: policyService}
}

func RegisterPolicyInternalRoutes(router gin.IRoutes, policyService *service.PolicyService) {
	if policyService == nil {
		return
	}

	handler := NewPolicyHandler(policyService)
	auth := middleware.AdminOrAPIKeyAuth("internal.policies.write")
	router.POST("/api/internal/policies/enforce", auth, handler.Enforce)
	router.POST("/api/internal/policies/batch-pause", auth, handler.BatchPause)
}

func (h *PolicyHandler) Enforce(c *gin.Context) {
	if h.policyService == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "service unavailable")
		return
	}

	var req enforcePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if err := h.policyService.EnforcePolicy(c.Request.Context(), req.UserID, req.Policy); err != nil {
		handlePolicyServiceError(c, err)
		return
	}

	response.Success(c, gin.H{
		"enforced": true,
		"policy":   req.Policy,
		"user_id":  req.UserID,
	})
}

func (h *PolicyHandler) BatchPause(c *gin.Context) {
	if h.policyService == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "service unavailable")
		return
	}

	if err := h.policyService.BatchPauseOverlimitUsers(c.Request.Context()); err != nil {
		handlePolicyServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"paused": true})
}

func handlePolicyServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidPolicy):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	case errors.Is(err, service.ErrUserNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
