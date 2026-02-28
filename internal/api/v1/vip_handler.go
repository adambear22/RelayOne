package v1

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	inputsanitize "nodepass-hub/internal/api/sanitize"
	"nodepass-hub/internal/service"
)

type VIPHandler struct {
	vipService *service.VIPService
}

type createVIPLevelRequest struct {
	Level               int                    `json:"level" binding:"required"`
	Name                string                 `json:"name" binding:"required"`
	TrafficQuota        int64                  `json:"traffic_quota" binding:"required"`
	MaxRules            int                    `json:"max_rules" binding:"required"`
	BandwidthLimit      int64                  `json:"bandwidth_limit" binding:"required"`
	MaxIngressNodes     int                    `json:"max_ingress_nodes"`
	MaxEgressNodes      int                    `json:"max_egress_nodes"`
	AccessibleNodeLevel int                    `json:"accessible_node_level"`
	TrafficRatio        float64                `json:"traffic_ratio"`
	CustomFeatures      map[string]interface{} `json:"custom_features"`
}

type updateVIPLevelRequest struct {
	Name                *string                 `json:"name"`
	TrafficQuota        *int64                  `json:"traffic_quota"`
	MaxRules            *int                    `json:"max_rules"`
	BandwidthLimit      *int64                  `json:"bandwidth_limit"`
	MaxIngressNodes     *int                    `json:"max_ingress_nodes"`
	MaxEgressNodes      *int                    `json:"max_egress_nodes"`
	AccessibleNodeLevel *int                    `json:"accessible_node_level"`
	TrafficRatio        *float64                `json:"traffic_ratio"`
	CustomFeatures      *map[string]interface{} `json:"custom_features"`
}

type upgradeUserVIPRequest struct {
	Level     int `json:"level" binding:"required"`
	ValidDays int `json:"valid_days" binding:"required"`
}

func NewVIPHandler(vipService *service.VIPService) *VIPHandler {
	return &VIPHandler{vipService: vipService}
}

func RegisterVIPRoutes(group *gin.RouterGroup, vipService *service.VIPService) {
	if vipService == nil {
		return
	}

	handler := NewVIPHandler(vipService)
	vip := group.Group("/vip")
	vip.Use(middleware.JWTAuth())

	vip.GET("/me", handler.Me)
	vip.GET("/", handler.ListLevels)
	vip.GET("/:level", handler.GetLevel)
	vip.POST("/", middleware.AuditLog("vip.level.create", "vip_level"), handler.CreateLevel)
	vip.PUT("/:level", middleware.AuditLog("vip.level.update", "vip_level"), handler.UpdateLevel)
	vip.DELETE("/:level", middleware.AuditLog("vip.level.delete", "vip_level"), handler.DeleteLevel)
	vip.POST("/users/:id/upgrade", middleware.AuditLog("user.vip_upgrade", "user"), handler.UpgradeUser)
}

// Me
// @Summary Me
// @Description Auto-generated endpoint documentation for Me.
// @Tags vip
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/vip/me [get]
func (h *VIPHandler) Me(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	item, err := h.vipService.GetUserEntitlement(c.Request.Context(), claims.UserID)
	if err != nil {
		handleVIPServiceError(c, err)
		return
	}
	response.Success(c, item)
}

// ListLevels
// @Summary ListLevels
// @Description Auto-generated endpoint documentation for ListLevels.
// @Tags vip
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/vip [get]
func (h *VIPHandler) ListLevels(c *gin.Context) {
	items, err := h.vipService.ListLevels(c.Request.Context())
	if err != nil {
		handleVIPServiceError(c, err)
		return
	}
	response.Success(c, items)
}

// GetLevel
// @Summary GetLevel
// @Description Auto-generated endpoint documentation for GetLevel.
// @Tags vip
// @Accept json
// @Produce json
// @Param level path string true "level"
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/vip/{level} [get]
func (h *VIPHandler) GetLevel(c *gin.Context) {
	level, err := parseLevelParam(c.Param("level"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid level")
		return
	}

	item, err := h.vipService.GetLevel(c.Request.Context(), level)
	if err != nil {
		handleVIPServiceError(c, err)
		return
	}
	response.Success(c, item)
}

// CreateLevel
// @Summary CreateLevel
// @Description Auto-generated endpoint documentation for CreateLevel.
// @Tags vip
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/vip [post]
func (h *VIPHandler) CreateLevel(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req createVIPLevelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.vipService.CreateLevel(c.Request.Context(), service.CreateVIPLevelRequest{
		Level:               req.Level,
		Name:                inputsanitize.Text(req.Name),
		TrafficQuota:        req.TrafficQuota,
		MaxRules:            req.MaxRules,
		BandwidthLimit:      req.BandwidthLimit,
		MaxIngressNodes:     req.MaxIngressNodes,
		MaxEgressNodes:      req.MaxEgressNodes,
		AccessibleNodeLevel: req.AccessibleNodeLevel,
		TrafficRatio:        req.TrafficRatio,
		CustomFeatures:      req.CustomFeatures,
	})
	if err != nil {
		handleVIPServiceError(c, err)
		return
	}
	response.Success(c, item)
}

// UpdateLevel
// @Summary UpdateLevel
// @Description Auto-generated endpoint documentation for UpdateLevel.
// @Tags vip
// @Accept json
// @Produce json
// @Param level path string true "level"
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/vip/{level} [put]
func (h *VIPHandler) UpdateLevel(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	level, err := parseLevelParam(c.Param("level"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid level")
		return
	}

	var req updateVIPLevelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.vipService.UpdateLevel(c.Request.Context(), level, service.UpdateVIPLevelRequest{
		Name:                inputsanitize.TextPtr(req.Name),
		TrafficQuota:        req.TrafficQuota,
		MaxRules:            req.MaxRules,
		BandwidthLimit:      req.BandwidthLimit,
		MaxIngressNodes:     req.MaxIngressNodes,
		MaxEgressNodes:      req.MaxEgressNodes,
		AccessibleNodeLevel: req.AccessibleNodeLevel,
		TrafficRatio:        req.TrafficRatio,
		CustomFeatures:      req.CustomFeatures,
	})
	if err != nil {
		handleVIPServiceError(c, err)
		return
	}
	response.Success(c, item)
}

// DeleteLevel
// @Summary DeleteLevel
// @Description Auto-generated endpoint documentation for DeleteLevel.
// @Tags vip
// @Accept json
// @Produce json
// @Param level path string true "level"
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/vip/{level} [delete]
func (h *VIPHandler) DeleteLevel(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	level, err := parseLevelParam(c.Param("level"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid level")
		return
	}

	if err := h.vipService.DeleteLevel(c.Request.Context(), level); err != nil {
		handleVIPServiceError(c, err)
		return
	}
	response.Success(c, gin.H{"deleted": true})
}

// UpgradeUser
// @Summary UpgradeUser
// @Description Auto-generated endpoint documentation for UpgradeUser.
// @Tags vip
// @Accept json
// @Produce json
// @Param id path string true "id"
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/vip/users/{id}/upgrade [post]
func (h *VIPHandler) UpgradeUser(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req upgradeUserVIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if err := h.vipService.UpgradeUser(c.Request.Context(), claims.UserID, c.Param("id"), req.Level, req.ValidDays); err != nil {
		handleVIPServiceError(c, err)
		return
	}
	response.Success(c, gin.H{"upgraded": true})
}

func handleVIPServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrVIPLevelNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "vip level not found")
	case errors.Is(err, service.ErrUserNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
	case errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidVIPLevelInput):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}

func parseLevelParam(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, service.ErrInvalidVIPLevelInput
	}
	level, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return level, nil
}
