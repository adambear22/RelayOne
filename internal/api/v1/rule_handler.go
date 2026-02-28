package v1

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	inputsanitize "nodepass-hub/internal/api/sanitize"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/service"
)

type RuleHandler struct {
	ruleService *service.RuleService
}

const (
	ruleActionStart   = "start"
	ruleActionStop    = "stop"
	ruleActionRestart = "restart"
	ruleActionSync    = "sync"
)

type createRuleRequest struct {
	Name          string  `json:"name" binding:"required"`
	Mode          string  `json:"mode" binding:"required"`
	IngressNodeID string  `json:"ingress_node_id" binding:"required"`
	TargetHost    string  `json:"target_host" binding:"required"`
	TargetPort    int     `json:"target_port" binding:"required"`
	EgressNodeID  *string `json:"egress_node_id"`
	LBGroupID     *string `json:"lb_group_id"`
	HopChainID    *string `json:"hop_chain_id"`
	NpTLS         *int    `json:"np_tls"`
	NpMode        *string `json:"np_mode"`
	NpMin         *int    `json:"np_min"`
	NpMax         *int    `json:"np_max"`
	NpRate        *int    `json:"np_rate"`
	NpNoTCP       *bool   `json:"np_notcp"`
	NpNoUDP       *bool   `json:"np_noudp"`
	NpLog         *string `json:"np_log"`
}

type updateRuleRequest struct {
	Name          *string `json:"name"`
	Mode          *string `json:"mode"`
	IngressNodeID *string `json:"ingress_node_id"`
	TargetHost    *string `json:"target_host"`
	TargetPort    *int    `json:"target_port"`
	EgressNodeID  *string `json:"egress_node_id"`
	LBGroupID     *string `json:"lb_group_id"`
	HopChainID    *string `json:"hop_chain_id"`
	NpTLS         *int    `json:"np_tls"`
	NpMode        *string `json:"np_mode"`
	NpMin         *int    `json:"np_min"`
	NpMax         *int    `json:"np_max"`
	NpRate        *int    `json:"np_rate"`
	NpNoTCP       *bool   `json:"np_notcp"`
	NpNoUDP       *bool   `json:"np_noudp"`
	NpLog         *string `json:"np_log"`
}

type batchDeleteRuleRequest struct {
	IDs []string `json:"ids"`
}

func NewRuleHandler(ruleService *service.RuleService) *RuleHandler {
	return &RuleHandler{ruleService: ruleService}
}

func RegisterRuleRoutes(group *gin.RouterGroup, ruleService *service.RuleService) {
	handler := NewRuleHandler(ruleService)
	rules := group.Group("/rules")
	rules.Use(middleware.JWTAuth())

	rules.POST("/", middleware.AuditLog("rule.create", "rule"), handler.Create)
	rules.GET("/", handler.List)
	rules.GET("/:id", handler.GetByID)
	rules.PUT("/:id", middleware.AuditLog("rule.update", "rule"), handler.Update)
	rules.DELETE("/:id", middleware.AuditLog("rule.delete", "rule"), handler.Delete)
	rules.POST("/:id/start", middleware.AuditLog("rule.start", "rule"), handler.Start)
	rules.POST("/:id/stop", middleware.AuditLog("rule.stop", "rule"), handler.Stop)
	rules.POST("/:id/restart", middleware.AuditLog("rule.restart", "rule"), handler.Restart)
	rules.POST("/:id/sync", middleware.AuditLog("rule.sync", "rule"), handler.Sync)
	rules.GET("/:id/instance", handler.GetInstanceInfo)
	rules.DELETE("/batch", middleware.AuditLog("rule.batch_delete", "rule"), handler.BatchDelete)
}

// Create
// @Summary Create
// @Description Auto-generated endpoint documentation for Create.
// @Tags rule
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/rules [post]
func (h *RuleHandler) Create(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req createRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	rule, err := h.ruleService.Create(c.Request.Context(), claims.UserID, service.CreateRuleRequest{
		Name:          inputsanitize.Text(req.Name),
		Mode:          inputsanitize.Text(req.Mode),
		IngressNodeID: inputsanitize.Text(req.IngressNodeID),
		TargetHost:    inputsanitize.Text(req.TargetHost),
		TargetPort:    req.TargetPort,
		EgressNodeID:  inputsanitize.TextPtr(req.EgressNodeID),
		LBGroupID:     inputsanitize.TextPtr(req.LBGroupID),
		HopChainID:    inputsanitize.TextPtr(req.HopChainID),
		NpTLS:         req.NpTLS,
		NpMode:        inputsanitize.TextPtr(req.NpMode),
		NpMin:         req.NpMin,
		NpMax:         req.NpMax,
		NpRate:        req.NpRate,
		NpNoTCP:       req.NpNoTCP,
		NpNoUDP:       req.NpNoUDP,
		NpLog:         inputsanitize.TextPtr(req.NpLog),
	})
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}

	response.Success(c, rule)
}

// List
// @Summary List
// @Description Auto-generated endpoint documentation for List.
// @Tags rule
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/rules [get]
func (h *RuleHandler) List(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	page := parseIntOrDefault(c.Query("page"), 1)
	pageSize := parseIntOrDefault(c.Query("page_size"), 20)

	filter := service.RuleListFilter{}
	if isAdmin(claims.Role) {
		if ownerID := strings.TrimSpace(c.Query("owner_id")); ownerID != "" {
			filter.OwnerID = &ownerID
		}
	} else {
		filter.OwnerID = &claims.UserID
	}

	if status := strings.TrimSpace(c.Query("status")); status != "" {
		filter.Status = &status
	}
	if mode := strings.TrimSpace(c.Query("mode")); mode != "" {
		filter.Mode = &mode
	}
	if nodeID := strings.TrimSpace(c.Query("node_id")); nodeID != "" {
		filter.NodeID = &nodeID
	}

	rules, total, err := h.ruleService.List(c.Request.Context(), page, pageSize, filter)
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}

	response.Paginated(c, rules, page, pageSize, total)
}

// GetByID
// @Summary GetByID
// @Description Auto-generated endpoint documentation for GetByID.
// @Tags rule
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
// @Router /api/v1/rules/{id} [get]
func (h *RuleHandler) GetByID(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	rule, err := h.authorizeRuleAccess(c, claims, c.Param("id"))
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}
	if rule == nil {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	response.Success(c, rule)
}

// Update
// @Summary Update
// @Description Auto-generated endpoint documentation for Update.
// @Tags rule
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
// @Router /api/v1/rules/{id} [put]
func (h *RuleHandler) Update(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	rule, err := h.authorizeRuleAccess(c, claims, c.Param("id"))
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}
	if rule == nil {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req updateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	rule, err = h.ruleService.Update(c.Request.Context(), c.Param("id"), service.UpdateRuleRequest{
		Name:          inputsanitize.TextPtr(req.Name),
		Mode:          inputsanitize.TextPtr(req.Mode),
		IngressNodeID: inputsanitize.TextPtr(req.IngressNodeID),
		TargetHost:    inputsanitize.TextPtr(req.TargetHost),
		TargetPort:    req.TargetPort,
		EgressNodeID:  inputsanitize.TextPtr(req.EgressNodeID),
		LBGroupID:     inputsanitize.TextPtr(req.LBGroupID),
		HopChainID:    inputsanitize.TextPtr(req.HopChainID),
		NpTLS:         req.NpTLS,
		NpMode:        inputsanitize.TextPtr(req.NpMode),
		NpMin:         req.NpMin,
		NpMax:         req.NpMax,
		NpRate:        req.NpRate,
		NpNoTCP:       req.NpNoTCP,
		NpNoUDP:       req.NpNoUDP,
		NpLog:         inputsanitize.TextPtr(req.NpLog),
	}, claims.UserID)
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}

	response.Success(c, rule)
}

// Delete
// @Summary Delete
// @Description Auto-generated endpoint documentation for Delete.
// @Tags rule
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
// @Router /api/v1/rules/{id} [delete]
func (h *RuleHandler) Delete(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	rule, err := h.authorizeRuleAccess(c, claims, c.Param("id"))
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}
	if rule == nil {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	if err := h.ruleService.Delete(c.Request.Context(), c.Param("id"), claims.UserID); err != nil {
		handleRuleServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"deleted": true})
}

// Start
// @Summary Start
// @Description Auto-generated endpoint documentation for Start.
// @Tags rule
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
// @Router /api/v1/rules/{id}/start [post]
func (h *RuleHandler) Start(c *gin.Context) {
	h.handleRuleAction(c, ruleActionStart)
}

// Stop
// @Summary Stop
// @Description Auto-generated endpoint documentation for Stop.
// @Tags rule
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
// @Router /api/v1/rules/{id}/stop [post]
func (h *RuleHandler) Stop(c *gin.Context) {
	h.handleRuleAction(c, ruleActionStop)
}

// Restart
// @Summary Restart
// @Description Auto-generated endpoint documentation for Restart.
// @Tags rule
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
// @Router /api/v1/rules/{id}/restart [post]
func (h *RuleHandler) Restart(c *gin.Context) {
	h.handleRuleAction(c, ruleActionRestart)
}

// Sync
// @Summary Sync
// @Description Auto-generated endpoint documentation for Sync.
// @Tags rule
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
// @Router /api/v1/rules/{id}/sync [post]
func (h *RuleHandler) Sync(c *gin.Context) {
	h.handleRuleAction(c, ruleActionSync)
}

// GetInstanceInfo
// @Summary GetInstanceInfo
// @Description Auto-generated endpoint documentation for GetInstanceInfo.
// @Tags rule
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
// @Router /api/v1/rules/{id}/instance [get]
func (h *RuleHandler) GetInstanceInfo(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	rule, err := h.authorizeRuleAccess(c, claims, c.Param("id"))
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}
	if rule == nil {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	info, err := h.ruleService.GetInstanceInfo(c.Request.Context(), c.Param("id"))
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}

	response.Success(c, info)
}

// BatchDelete
// @Summary BatchDelete
// @Description Auto-generated endpoint documentation for BatchDelete.
// @Tags rule
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/rules/batch [delete]
func (h *RuleHandler) BatchDelete(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req batchDeleteRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if !isAdmin(claims.Role) {
		for _, id := range req.IDs {
			rule, err := h.authorizeRuleAccess(c, claims, id)
			if err != nil {
				handleRuleServiceError(c, err)
				return
			}
			if rule == nil {
				response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
				return
			}
		}
	}

	if err := h.ruleService.BatchDelete(c.Request.Context(), claims.UserID, req.IDs); err != nil {
		handleRuleServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"deleted": len(req.IDs)})
}

func (h *RuleHandler) handleRuleAction(c *gin.Context, action string) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	rule, err := h.authorizeRuleAccess(c, claims, c.Param("id"))
	if err != nil {
		handleRuleServiceError(c, err)
		return
	}
	if rule == nil {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	err = nil
	switch action {
	case ruleActionStart:
		err = h.ruleService.Start(c.Request.Context(), c.Param("id"), claims.UserID)
	case ruleActionStop:
		err = h.ruleService.Stop(c.Request.Context(), c.Param("id"), claims.UserID)
	case ruleActionRestart:
		err = h.ruleService.Restart(c.Request.Context(), c.Param("id"), claims.UserID)
	case ruleActionSync:
		err = h.ruleService.SyncRule(c.Request.Context(), c.Param("id"))
	default:
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid action")
		return
	}

	if err != nil {
		handleRuleServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"action": action, "ok": true})
}

func (h *RuleHandler) authorizeRuleAccess(c *gin.Context, claims *middleware.Claims, ruleID string) (*model.ForwardingRule, error) {
	rule, err := h.ruleService.GetByID(c.Request.Context(), ruleID)
	if err != nil {
		return nil, err
	}

	if isAdmin(claims.Role) {
		return rule, nil
	}
	if rule.OwnerID.String() != claims.UserID {
		return nil, nil
	}

	return rule, nil
}

func handleRuleServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrRuleNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrRuleNotFound, "rule not found")
	case errors.Is(err, service.ErrRuleLimitExceeded):
		response.Fail(c, http.StatusConflict, response.ErrRuleLimitExceeded, "rule limit exceeded")
	case errors.Is(err, service.ErrRuleNotEditable):
		response.Fail(c, http.StatusConflict, response.ErrInternal, "rule cannot be modified")
	case errors.Is(err, service.ErrNodeOffline):
		response.Fail(c, http.StatusConflict, response.ErrNodeOffline, "node offline")
	case errors.Is(err, service.ErrLBNoActiveMembers),
		errors.Is(err, service.ErrHopChainNodeOffline):
		response.Fail(c, http.StatusConflict, response.ErrNodeOffline, "node offline")
	case errors.Is(err, service.ErrNodeNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrNodeNotFound, "node not found")
	case errors.Is(err, service.ErrPortExhausted):
		response.Fail(c, http.StatusConflict, response.ErrPortExhausted, "port exhausted")
	case errors.Is(err, service.ErrRuleSyncTimeout):
		response.Fail(c, http.StatusGatewayTimeout, response.ErrInternal, "rule sync timeout")
	case errors.Is(err, service.ErrHopChainNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "hop chain not found")
	case errors.Is(err, service.ErrLBGroupNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "lb group not found")
	case errors.Is(err, service.ErrInvalidRuleID),
		errors.Is(err, service.ErrInvalidRuleInput),
		errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidNodeID),
		errors.Is(err, service.ErrInvalidNodePassParams),
		errors.Is(err, service.ErrInvalidHopChainInput),
		errors.Is(err, service.ErrInvalidLBInput):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
