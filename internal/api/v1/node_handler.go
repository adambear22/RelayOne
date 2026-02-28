package v1

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	inputsanitize "nodepass-hub/internal/api/sanitize"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/service"
)

type NodeHandler struct {
	nodeService *service.NodeService
}

type createNodeRequest struct {
	Name         string  `json:"name" binding:"required"`
	Type         string  `json:"type"`
	Host         string  `json:"host" binding:"required"`
	APIPort      int     `json:"api_port" binding:"required"`
	Arch         string  `json:"arch"`
	PortRangeMin *int    `json:"port_range_min"`
	PortRangeMax *int    `json:"port_range_max"`
	IsSelfHosted bool    `json:"is_self_hosted"`
	VIPLevelReq  int     `json:"vip_level_req"`
	TrafficRatio float64 `json:"traffic_ratio"`
}

type updateNodeRequest struct {
	Name         *string  `json:"name"`
	Type         *string  `json:"type"`
	Host         *string  `json:"host"`
	APIPort      *int     `json:"api_port"`
	Arch         *string  `json:"arch"`
	PortRangeMin *int     `json:"port_range_min"`
	PortRangeMax *int     `json:"port_range_max"`
	IsSelfHosted *bool    `json:"is_self_hosted"`
	VIPLevelReq  *int     `json:"vip_level_req"`
	TrafficRatio *float64 `json:"traffic_ratio"`
}

type tcpTestRequest struct {
	TargetHost string `json:"target_host" binding:"required"`
	TargetPort int    `json:"target_port" binding:"required"`
	TimeoutSec int    `json:"timeout_sec"`
}

func NewNodeHandler(nodeService *service.NodeService) *NodeHandler {
	return &NodeHandler{nodeService: nodeService}
}

func RegisterNodeRoutes(group *gin.RouterGroup, nodeService *service.NodeService) {
	handler := NewNodeHandler(nodeService)
	nodes := group.Group("/nodes")

	nodes.GET("/:id/install.sh", handler.GenerateInstallScript)

	nodes.Use(middleware.JWTAuth())
	nodes.POST("/", handler.Create)
	nodes.GET("/", handler.List)
	nodes.GET("/:id", handler.GetByID)
	nodes.PUT("/:id", middleware.AuditLog("node.update", "node"), handler.Update)
	nodes.DELETE("/:id", middleware.AuditLog("node.delete", "node"), handler.Delete)
	nodes.POST("/:id/tcp-test", handler.TestTCPConnectivity)
	nodes.GET("/:id/deploy-logs", handler.ListDeployLogs)
}

// Create
// @Summary Create
// @Description Auto-generated endpoint documentation for Create.
// @Tags node
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/nodes [post]
func (h *NodeHandler) Create(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req createNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	node, err := h.nodeService.Create(c.Request.Context(), claims.UserID, service.CreateNodeRequest{
		Name:         inputsanitize.Text(req.Name),
		Type:         inputsanitize.Text(req.Type),
		Host:         inputsanitize.Text(req.Host),
		APIPort:      req.APIPort,
		Arch:         inputsanitize.Text(req.Arch),
		PortRangeMin: req.PortRangeMin,
		PortRangeMax: req.PortRangeMax,
		IsSelfHosted: req.IsSelfHosted,
		VIPLevelReq:  req.VIPLevelReq,
		TrafficRatio: req.TrafficRatio,
	})
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}

	response.Success(c, node)
}

// List
// @Summary List
// @Description Auto-generated endpoint documentation for List.
// @Tags node
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/nodes [get]
func (h *NodeHandler) List(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	page := parseIntOrDefault(c.Query("page"), 1)
	pageSize := parseIntOrDefault(c.Query("page_size"), 20)

	filter := service.NodeListFilter{}
	if isAdmin(claims.Role) {
		if ownerID := strings.TrimSpace(c.Query("owner_id")); ownerID != "" {
			filter.OwnerID = &ownerID
		}
	} else {
		filter.OwnerID = &claims.UserID
	}

	if t := strings.TrimSpace(c.Query("type")); t != "" {
		filter.Type = &t
	}
	if st := strings.TrimSpace(c.Query("status")); st != "" {
		filter.Status = &st
	}
	if ds := strings.TrimSpace(c.Query("deploy_status")); ds != "" {
		filter.DeployStatus = &ds
	}

	nodes, total, err := h.nodeService.List(c.Request.Context(), page, pageSize, filter)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}

	response.Paginated(c, nodes, page, pageSize, total)
}

// GetByID
// @Summary GetByID
// @Description Auto-generated endpoint documentation for GetByID.
// @Tags node
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
// @Router /api/v1/nodes/{id} [get]
func (h *NodeHandler) GetByID(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	nodeID := c.Param("id")
	allowed, err := h.authorizeNodeAccess(c, claims, nodeID)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}
	if !allowed {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	node, err := h.nodeService.GetByID(c.Request.Context(), nodeID)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}

	response.Success(c, node)
}

// Update
// @Summary Update
// @Description Auto-generated endpoint documentation for Update.
// @Tags node
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
// @Router /api/v1/nodes/{id} [put]
func (h *NodeHandler) Update(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	nodeID := c.Param("id")
	allowed, err := h.authorizeNodeAccess(c, claims, nodeID)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}
	if !allowed {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req updateNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	node, err := h.nodeService.Update(c.Request.Context(), nodeID, service.UpdateNodeRequest{
		Name:         inputsanitize.TextPtr(req.Name),
		Type:         inputsanitize.TextPtr(req.Type),
		Host:         inputsanitize.TextPtr(req.Host),
		APIPort:      req.APIPort,
		Arch:         inputsanitize.TextPtr(req.Arch),
		PortRangeMin: req.PortRangeMin,
		PortRangeMax: req.PortRangeMax,
		IsSelfHosted: req.IsSelfHosted,
		VIPLevelReq:  req.VIPLevelReq,
		TrafficRatio: req.TrafficRatio,
	})
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}

	response.Success(c, node)
}

// Delete
// @Summary Delete
// @Description Auto-generated endpoint documentation for Delete.
// @Tags node
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
// @Router /api/v1/nodes/{id} [delete]
func (h *NodeHandler) Delete(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	nodeID := c.Param("id")
	allowed, err := h.authorizeNodeAccess(c, claims, nodeID)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}
	if !allowed {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	if err := h.nodeService.Delete(c.Request.Context(), nodeID); err != nil {
		handleNodeServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"deleted": true})
}

// GenerateInstallScript
// @Summary GenerateInstallScript
// @Description Auto-generated endpoint documentation for GenerateInstallScript.
// @Tags node
// @Accept json
// @Produce json
// @Param id path string true "id"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/nodes/{id}/install.sh [get]
func (h *NodeHandler) GenerateInstallScript(c *gin.Context) {
	nodeID := c.Param("id")
	installToken := strings.TrimSpace(c.Query("installToken"))
	if installToken == "" {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	script, err := h.nodeService.GenerateInstallScript(c.Request.Context(), nodeID, installToken)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}

	fileName := "nodepass-agent-" + nodeID + ".sh"
	c.Header("Content-Type", "text/x-shellscript")
	c.Header("Content-Disposition", "attachment; filename=\""+fileName+"\"")
	c.String(http.StatusOK, script)
}

// TestTCPConnectivity
// @Summary TestTCPConnectivity
// @Description Auto-generated endpoint documentation for TestTCPConnectivity.
// @Tags node
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
// @Router /api/v1/nodes/{id}/tcp-test [post]
func (h *NodeHandler) TestTCPConnectivity(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	nodeID := c.Param("id")
	allowed, err := h.authorizeNodeAccess(c, claims, nodeID)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}
	if !allowed {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req tcpTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	timeout := 5 * time.Second
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}

	result, err := h.nodeService.TestTCPConnectivity(
		c.Request.Context(),
		nodeID,
		inputsanitize.Text(req.TargetHost),
		req.TargetPort,
		timeout,
	)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}

	response.Success(c, result)
}

// ListDeployLogs
// @Summary ListDeployLogs
// @Description Auto-generated endpoint documentation for ListDeployLogs.
// @Tags node
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
// @Router /api/v1/nodes/{id}/deploy-logs [get]
func (h *NodeHandler) ListDeployLogs(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	nodeID := c.Param("id")
	allowed, err := h.authorizeNodeAccess(c, claims, nodeID)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}
	if !allowed {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	page := parseIntOrDefault(c.Query("page"), 1)
	pageSize := parseIntOrDefault(c.Query("page_size"), 20)

	logs, total, err := h.nodeService.ListDeployLogs(c.Request.Context(), nodeID, page, pageSize)
	if err != nil {
		handleNodeServiceError(c, err)
		return
	}

	response.Paginated(c, logs, page, pageSize, total)
}

func (h *NodeHandler) authorizeNodeAccess(c *gin.Context, claims *middleware.Claims, nodeID string) (bool, error) {
	if claims == nil {
		return false, nil
	}
	if strings.EqualFold(claims.Role, string(model.UserRoleAdmin)) {
		return true, nil
	}
	return h.nodeService.IsOwner(c.Request.Context(), nodeID, claims.UserID)
}

func handleNodeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrNodeNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrNodeNotFound, "node not found")
	case errors.Is(err, service.ErrInstallForbidden):
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
	case errors.Is(err, service.ErrInvalidNodeID), errors.Is(err, service.ErrInvalidUserID), errors.Is(err, service.ErrInvalidUserInput):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
