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

type HopChainHandler struct {
	hopService *service.HopChainService
}

type createHopChainRequest struct {
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
}

type updateHopChainRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type replaceHopChainNodesRequest struct {
	Nodes []service.HopChainNodeInput `json:"nodes" binding:"required"`
}

func NewHopChainHandler(hopService *service.HopChainService) *HopChainHandler {
	return &HopChainHandler{hopService: hopService}
}

func RegisterHopChainRoutes(group *gin.RouterGroup, hopService *service.HopChainService) {
	if hopService == nil {
		return
	}

	handler := NewHopChainHandler(hopService)
	hop := group.Group("/hop-chains")
	hop.Use(middleware.JWTAuth())

	hop.GET("/", handler.List)
	hop.POST("/", middleware.AuditLog("hop_chain.create", "hop_chain"), handler.Create)
	hop.GET("/:id", handler.GetByID)
	hop.PUT("/:id", middleware.AuditLog("hop_chain.update", "hop_chain"), handler.Update)
	hop.DELETE("/:id", middleware.AuditLog("hop_chain.delete", "hop_chain"), handler.Delete)
	hop.GET("/:id/nodes", handler.ListNodes)
	hop.PUT("/:id/nodes", middleware.AuditLog("hop_chain.nodes_replace", "hop_chain_node"), handler.ReplaceNodes)
	hop.PATCH("/:id/nodes/reorder", middleware.AuditLog("hop_chain.nodes_reorder", "hop_chain_node"), handler.ReorderNodes)
}

// List
// @Summary List
// @Description Auto-generated endpoint documentation for List.
// @Tags hop-chain
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/hop-chains [get]
func (h *HopChainHandler) List(c *gin.Context) {
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

	items, total, err := h.hopService.List(c.Request.Context(), page, pageSize, ownerID)
	if err != nil {
		handleHopChainServiceError(c, err)
		return
	}

	response.Paginated(c, items, page, pageSize, total)
}

// Create
// @Summary Create
// @Description Auto-generated endpoint documentation for Create.
// @Tags hop-chain
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/hop-chains [post]
func (h *HopChainHandler) Create(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req createHopChainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.hopService.Create(c.Request.Context(), claims.UserID, service.CreateHopChainRequest{
		Name:        inputsanitize.Text(req.Name),
		Description: inputsanitize.TextPtr(req.Description),
	})
	if err != nil {
		handleHopChainServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// GetByID
// @Summary GetByID
// @Description Auto-generated endpoint documentation for GetByID.
// @Tags hop-chain
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
// @Router /api/v1/hop-chains/{id} [get]
func (h *HopChainHandler) GetByID(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureHopAccess(c, claims, c.Param("id")) {
		return
	}

	item, err := h.hopService.GetByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		handleHopChainServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// Update
// @Summary Update
// @Description Auto-generated endpoint documentation for Update.
// @Tags hop-chain
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
// @Router /api/v1/hop-chains/{id} [put]
func (h *HopChainHandler) Update(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureHopAccess(c, claims, c.Param("id")) {
		return
	}

	var req updateHopChainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.hopService.Update(c.Request.Context(), c.Param("id"), service.UpdateHopChainRequest{
		Name:        inputsanitize.TextPtr(req.Name),
		Description: inputsanitize.TextPtr(req.Description),
	})
	if err != nil {
		handleHopChainServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// Delete
// @Summary Delete
// @Description Auto-generated endpoint documentation for Delete.
// @Tags hop-chain
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
// @Router /api/v1/hop-chains/{id} [delete]
func (h *HopChainHandler) Delete(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureHopAccess(c, claims, c.Param("id")) {
		return
	}

	if err := h.hopService.Delete(c.Request.Context(), c.Param("id")); err != nil {
		handleHopChainServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"deleted": true})
}

// ListNodes
// @Summary ListNodes
// @Description Auto-generated endpoint documentation for ListNodes.
// @Tags hop-chain
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
// @Router /api/v1/hop-chains/{id}/nodes [get]
func (h *HopChainHandler) ListNodes(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureHopAccess(c, claims, c.Param("id")) {
		return
	}

	items, err := h.hopService.ListNodes(c.Request.Context(), c.Param("id"))
	if err != nil {
		handleHopChainServiceError(c, err)
		return
	}

	response.Success(c, items)
}

// ReplaceNodes
// @Summary ReplaceNodes
// @Description Auto-generated endpoint documentation for ReplaceNodes.
// @Tags hop-chain
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
// @Router /api/v1/hop-chains/{id}/nodes [put]
func (h *HopChainHandler) ReplaceNodes(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureHopAccess(c, claims, c.Param("id")) {
		return
	}

	var req replaceHopChainNodesRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Nodes) == 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	for idx := range req.Nodes {
		req.Nodes[idx].NodeID = inputsanitize.Text(req.Nodes[idx].NodeID)
		if req.Nodes[idx].ID != nil {
			req.Nodes[idx].ID = inputsanitize.TextPtr(req.Nodes[idx].ID)
		}
	}

	if err := h.hopService.ReplaceNodes(c.Request.Context(), c.Param("id"), req.Nodes); err != nil {
		handleHopChainServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"updated": len(req.Nodes)})
}

// ReorderNodes
// @Summary ReorderNodes
// @Description Auto-generated endpoint documentation for ReorderNodes.
// @Tags hop-chain
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
// @Router /api/v1/hop-chains/{id}/nodes/reorder [patch]
func (h *HopChainHandler) ReorderNodes(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !h.ensureHopAccess(c, claims, c.Param("id")) {
		return
	}

	var items []service.HopChainNodeReorderItem
	if err := c.ShouldBindJSON(&items); err != nil || len(items) == 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}
	for i := range items {
		items[i].ID = inputsanitize.Text(items[i].ID)
	}

	if err := h.hopService.ReorderNodes(c.Request.Context(), c.Param("id"), items); err != nil {
		handleHopChainServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"updated": len(items)})
}

func (h *HopChainHandler) ensureHopAccess(c *gin.Context, claims *middleware.Claims, chainID string) bool {
	if claims == nil {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return false
	}
	if strings.EqualFold(claims.Role, string(model.UserRoleAdmin)) {
		return true
	}

	owner, err := h.hopService.IsOwner(c.Request.Context(), chainID, claims.UserID)
	if err != nil {
		handleHopChainServiceError(c, err)
		return false
	}
	if !owner {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return false
	}

	return true
}

func handleHopChainServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrHopChainNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "hop chain not found")
	case errors.Is(err, service.ErrHopChainNodeNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "hop chain node not found")
	case errors.Is(err, service.ErrNodeNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrNodeNotFound, "node not found")
	case errors.Is(err, service.ErrHopChainNodeOffline):
		response.Fail(c, http.StatusConflict, response.ErrNodeOffline, "hop chain node offline")
	case errors.Is(err, service.ErrInvalidHopChainInput),
		errors.Is(err, service.ErrHopChainInvalidOrder),
		errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidNodeID):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
