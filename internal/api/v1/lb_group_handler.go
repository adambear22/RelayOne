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

type LBGroupHandler struct {
	lbService *service.LBService
}

type createLBGroupRequest struct {
	Name                string `json:"name" binding:"required"`
	Strategy            string `json:"strategy"`
	HealthCheckInterval int    `json:"health_check_interval"`
}

type updateLBGroupRequest struct {
	Name                *string `json:"name"`
	Strategy            *string `json:"strategy"`
	HealthCheckInterval *int    `json:"health_check_interval"`
}

type addLBMemberRequest struct {
	NodeID   string `json:"node_id" binding:"required"`
	Weight   int    `json:"weight"`
	IsActive *bool  `json:"is_active"`
}

type updateLBMemberRequest struct {
	Weight   *int  `json:"weight"`
	IsActive *bool `json:"is_active"`
}

func NewLBGroupHandler(lbService *service.LBService) *LBGroupHandler {
	return &LBGroupHandler{lbService: lbService}
}

func RegisterLBGroupRoutes(group *gin.RouterGroup, lbService *service.LBService) {
	if lbService == nil {
		return
	}

	handler := NewLBGroupHandler(lbService)
	lb := group.Group("/lb-groups")
	lb.Use(middleware.JWTAuth())

	lb.GET("/", handler.List)
	lb.POST("/", middleware.AuditLog("lb_group.create", "lb_group"), handler.Create)
	lb.GET("/:id", handler.GetByID)
	lb.PUT("/:id", middleware.AuditLog("lb_group.update", "lb_group"), handler.Update)
	lb.DELETE("/:id", middleware.AuditLog("lb_group.delete", "lb_group"), handler.Delete)
	lb.GET("/:id/members", handler.ListMembers)
	lb.POST("/:id/members", middleware.AuditLog("lb_group.member_add", "lb_group_member"), handler.AddMember)
	lb.PUT("/:id/members/:memberID", middleware.AuditLog("lb_group.member_update", "lb_group_member"), handler.UpdateMember)
	lb.DELETE("/:id/members/:memberID", middleware.AuditLog("lb_group.member_delete", "lb_group_member"), handler.DeleteMember)
}

// List
// @Summary List
// @Description Auto-generated endpoint documentation for List.
// @Tags lb-group
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/lb-groups [get]
func (h *LBGroupHandler) List(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	page := parseIntOrDefault(c.Query("page"), 1)
	pageSize := parseIntOrDefault(c.Query("page_size"), 20)

	var ownerID *string
	if isAdmin(claims.Role) {
		if raw := strings.TrimSpace(c.Query("owner_id")); raw != "" {
			ownerID = &raw
		}
	} else {
		ownerID = &claims.UserID
	}

	items, total, err := h.lbService.ListGroups(c.Request.Context(), page, pageSize, ownerID)
	if err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Paginated(c, items, page, pageSize, total)
}

// Create
// @Summary Create
// @Description Auto-generated endpoint documentation for Create.
// @Tags lb-group
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/lb-groups [post]
func (h *LBGroupHandler) Create(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req createLBGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.lbService.CreateGroup(c.Request.Context(), claims.UserID, service.CreateLBGroupRequest{
		Name:                inputsanitize.Text(req.Name),
		Strategy:            inputsanitize.Text(req.Strategy),
		HealthCheckInterval: req.HealthCheckInterval,
	})
	if err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// GetByID
// @Summary GetByID
// @Description Auto-generated endpoint documentation for GetByID.
// @Tags lb-group
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
// @Router /api/v1/lb-groups/{id} [get]
func (h *LBGroupHandler) GetByID(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	if !h.ensureLBAccess(c, claims, c.Param("id")) {
		return
	}

	item, err := h.lbService.GetGroup(c.Request.Context(), c.Param("id"))
	if err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// Update
// @Summary Update
// @Description Auto-generated endpoint documentation for Update.
// @Tags lb-group
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
// @Router /api/v1/lb-groups/{id} [put]
func (h *LBGroupHandler) Update(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureLBAccess(c, claims, c.Param("id")) {
		return
	}

	var req updateLBGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.lbService.UpdateGroup(c.Request.Context(), c.Param("id"), service.UpdateLBGroupRequest{
		Name:                inputsanitize.TextPtr(req.Name),
		Strategy:            inputsanitize.TextPtr(req.Strategy),
		HealthCheckInterval: req.HealthCheckInterval,
	})
	if err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// Delete
// @Summary Delete
// @Description Auto-generated endpoint documentation for Delete.
// @Tags lb-group
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
// @Router /api/v1/lb-groups/{id} [delete]
func (h *LBGroupHandler) Delete(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureLBAccess(c, claims, c.Param("id")) {
		return
	}

	if err := h.lbService.DeleteGroup(c.Request.Context(), c.Param("id")); err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"deleted": true})
}

// ListMembers
// @Summary ListMembers
// @Description Auto-generated endpoint documentation for ListMembers.
// @Tags lb-group
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
// @Router /api/v1/lb-groups/{id}/members [get]
func (h *LBGroupHandler) ListMembers(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureLBAccess(c, claims, c.Param("id")) {
		return
	}

	items, err := h.lbService.ListMembers(c.Request.Context(), c.Param("id"))
	if err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Success(c, items)
}

// AddMember
// @Summary AddMember
// @Description Auto-generated endpoint documentation for AddMember.
// @Tags lb-group
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
// @Router /api/v1/lb-groups/{id}/members [post]
func (h *LBGroupHandler) AddMember(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureLBAccess(c, claims, c.Param("id")) {
		return
	}

	var req addLBMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.lbService.AddMember(c.Request.Context(), c.Param("id"), service.CreateLBGroupMemberRequest{
		NodeID:   inputsanitize.Text(req.NodeID),
		Weight:   req.Weight,
		IsActive: req.IsActive,
	})
	if err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// UpdateMember
// @Summary UpdateMember
// @Description Auto-generated endpoint documentation for UpdateMember.
// @Tags lb-group
// @Accept json
// @Produce json
// @Param id path string true "id"
// @Param memberID path string true "memberID"
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/lb-groups/{id}/members/{memberID} [put]
func (h *LBGroupHandler) UpdateMember(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureLBAccess(c, claims, c.Param("id")) {
		return
	}

	var req updateLBMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.lbService.UpdateMember(c.Request.Context(), c.Param("id"), c.Param("memberID"), service.UpdateLBGroupMemberRequest{
		Weight:   req.Weight,
		IsActive: req.IsActive,
	})
	if err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// DeleteMember
// @Summary DeleteMember
// @Description Auto-generated endpoint documentation for DeleteMember.
// @Tags lb-group
// @Accept json
// @Produce json
// @Param id path string true "id"
// @Param memberID path string true "memberID"
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/lb-groups/{id}/members/{memberID} [delete]
func (h *LBGroupHandler) DeleteMember(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureLBAccess(c, claims, c.Param("id")) {
		return
	}

	if err := h.lbService.DeleteMember(c.Request.Context(), c.Param("id"), c.Param("memberID")); err != nil {
		handleLBServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"deleted": true})
}

func (h *LBGroupHandler) ensureLBAccess(c *gin.Context, claims *middleware.Claims, groupID string) bool {
	if claims == nil {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return false
	}
	if strings.EqualFold(claims.Role, string(model.UserRoleAdmin)) {
		return true
	}

	owner, err := h.lbService.IsOwner(c.Request.Context(), groupID, claims.UserID)
	if err != nil {
		handleLBServiceError(c, err)
		return false
	}
	if !owner {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return false
	}

	return true
}

func handleLBServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrLBGroupNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "lb group not found")
	case errors.Is(err, service.ErrLBMemberNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "lb group member not found")
	case errors.Is(err, service.ErrLBNoActiveMembers):
		response.Fail(c, http.StatusConflict, response.ErrNodeOffline, "no active lb members")
	case errors.Is(err, service.ErrNodeNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrNodeNotFound, "node not found")
	case errors.Is(err, service.ErrInvalidLBInput),
		errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidNodeID):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
