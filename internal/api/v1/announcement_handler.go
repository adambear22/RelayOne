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
	"nodepass-hub/internal/service"
)

type AnnouncementHandler struct {
	announcementService *service.AnnouncementService
}

type createAnnouncementRequest struct {
	Type      string  `json:"type" binding:"required"`
	Title     string  `json:"title" binding:"required"`
	Content   string  `json:"content" binding:"required"`
	IsEnabled *bool   `json:"is_enabled"`
	StartsAt  *string `json:"starts_at"`
	EndsAt    *string `json:"ends_at"`
}

type updateAnnouncementRequest struct {
	Type      *string `json:"type"`
	Title     *string `json:"title"`
	Content   *string `json:"content"`
	IsEnabled *bool   `json:"is_enabled"`
	StartsAt  *string `json:"starts_at"`
	EndsAt    *string `json:"ends_at"`
}

type toggleAnnouncementRequest struct {
	Enabled *bool `json:"enabled"`
}

func NewAnnouncementHandler(announcementService *service.AnnouncementService) *AnnouncementHandler {
	return &AnnouncementHandler{
		announcementService: announcementService,
	}
}

func RegisterAnnouncementRoutes(group *gin.RouterGroup, announcementService *service.AnnouncementService) {
	if announcementService == nil {
		return
	}

	handler := NewAnnouncementHandler(announcementService)
	ann := group.Group("/announcements")

	ann.GET("/active", handler.ListActive)

	ann.Use(middleware.JWTAuth())
	ann.GET("/", handler.List)
	ann.GET("/:id", handler.GetByID)
	ann.POST("/", middleware.AuditLog("announcement.create", "announcement"), handler.Create)
	ann.PUT("/:id", middleware.AuditLog("announcement.update", "announcement"), handler.Update)
	ann.DELETE("/:id", middleware.AuditLog("announcement.delete", "announcement"), handler.Delete)
	ann.PATCH("/:id/toggle", middleware.AuditLog("announcement.toggle", "announcement"), handler.Toggle)
}

// ListActive
// @Summary ListActive
// @Description Auto-generated endpoint documentation for ListActive.
// @Tags announcement
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/announcements/active [get]
func (h *AnnouncementHandler) ListActive(c *gin.Context) {
	items, err := h.announcementService.ListActive(c.Request.Context())
	if err != nil {
		handleAnnouncementServiceError(c, err)
		return
	}
	response.Success(c, items)
}

// List
// @Summary List
// @Description Auto-generated endpoint documentation for List.
// @Tags announcement
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/announcements [get]
func (h *AnnouncementHandler) List(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	page := parseIntOrDefault(c.Query("page"), 1)
	pageSize := parseIntOrDefault(c.Query("page_size"), 20)

	items, total, err := h.announcementService.List(c.Request.Context(), page, pageSize)
	if err != nil {
		handleAnnouncementServiceError(c, err)
		return
	}
	response.Paginated(c, items, page, pageSize, total)
}

// GetByID
// @Summary GetByID
// @Description Auto-generated endpoint documentation for GetByID.
// @Tags announcement
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
// @Router /api/v1/announcements/{id} [get]
func (h *AnnouncementHandler) GetByID(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	item, err := h.announcementService.GetByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		handleAnnouncementServiceError(c, err)
		return
	}
	response.Success(c, item)
}

// Create
// @Summary Create
// @Description Auto-generated endpoint documentation for Create.
// @Tags announcement
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/announcements [post]
func (h *AnnouncementHandler) Create(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req createAnnouncementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	startsAt, err := parseAnnouncementTime(req.StartsAt)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid starts_at")
		return
	}
	endsAt, err := parseAnnouncementTime(req.EndsAt)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid ends_at")
		return
	}

	item, err := h.announcementService.Create(c.Request.Context(), claims.UserID, service.CreateAnnouncementRequest{
		Type:      inputsanitize.Text(req.Type),
		Title:     inputsanitize.Text(req.Title),
		Content:   inputsanitize.Markdown(req.Content),
		IsEnabled: req.IsEnabled,
		StartsAt:  startsAt,
		EndsAt:    endsAt,
	})
	if err != nil {
		handleAnnouncementServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// Update
// @Summary Update
// @Description Auto-generated endpoint documentation for Update.
// @Tags announcement
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
// @Router /api/v1/announcements/{id} [put]
func (h *AnnouncementHandler) Update(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req updateAnnouncementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	startsAt, err := parseAnnouncementTime(req.StartsAt)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid starts_at")
		return
	}
	endsAt, err := parseAnnouncementTime(req.EndsAt)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid ends_at")
		return
	}

	item, err := h.announcementService.Update(c.Request.Context(), claims.UserID, c.Param("id"), service.UpdateAnnouncementRequest{
		Type:      inputsanitize.TextPtr(req.Type),
		Title:     inputsanitize.TextPtr(req.Title),
		Content:   inputsanitize.MarkdownPtr(req.Content),
		IsEnabled: req.IsEnabled,
		StartsAt:  startsAt,
		EndsAt:    endsAt,
	})
	if err != nil {
		handleAnnouncementServiceError(c, err)
		return
	}

	response.Success(c, item)
}

// Delete
// @Summary Delete
// @Description Auto-generated endpoint documentation for Delete.
// @Tags announcement
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
// @Router /api/v1/announcements/{id} [delete]
func (h *AnnouncementHandler) Delete(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	if err := h.announcementService.Delete(c.Request.Context(), claims.UserID, c.Param("id")); err != nil {
		handleAnnouncementServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"deleted": true})
}

// Toggle
// @Summary Toggle
// @Description Auto-generated endpoint documentation for Toggle.
// @Tags announcement
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
// @Router /api/v1/announcements/{id}/toggle [patch]
func (h *AnnouncementHandler) Toggle(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req toggleAnnouncementRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	item, err := h.announcementService.Toggle(c.Request.Context(), claims.UserID, c.Param("id"), *req.Enabled)
	if err != nil {
		handleAnnouncementServiceError(c, err)
		return
	}

	response.Success(c, item)
}

func parseAnnouncementTime(raw *string) (*time.Time, error) {
	if raw == nil {
		return nil, nil
	}
	value := strings.TrimSpace(*raw)
	if value == "" {
		return nil, nil
	}

	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	utc := ts.UTC()
	return &utc, nil
}

func handleAnnouncementServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrAnnouncementNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "announcement not found")
	case errors.Is(err, service.ErrInvalidAnnouncementReq),
		errors.Is(err, service.ErrInvalidUserID):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
