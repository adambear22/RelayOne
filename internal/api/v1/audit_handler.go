package v1

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	"nodepass-hub/internal/service"
)

type AuditHandler struct {
	auditService *service.AuditService
}

func NewAuditHandler(auditService *service.AuditService) *AuditHandler {
	return &AuditHandler{auditService: auditService}
}

func RegisterAuditRoutes(group *gin.RouterGroup, auditService *service.AuditService) {
	if auditService == nil {
		return
	}

	handler := NewAuditHandler(auditService)
	audit := group.Group("/audit")
	audit.Use(middleware.JWTAuth())
	audit.GET("/", handler.List)
}

// List
// @Summary List
// @Description Auto-generated endpoint documentation for List.
// @Tags audit
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/audit [get]
func (h *AuditHandler) List(c *gin.Context) {
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

	filter := service.AuditFilter{}
	if raw := strings.TrimSpace(c.Query("user_id")); raw != "" {
		filter.UserID = &raw
	}
	if raw := strings.TrimSpace(c.Query("resource_type")); raw != "" {
		filter.ResourceType = &raw
	}
	if raw := strings.TrimSpace(c.Query("resource_id")); raw != "" {
		filter.ResourceID = &raw
	}
	if raw := strings.TrimSpace(c.Query("action")); raw != "" {
		filter.Action = &raw
	}
	if raw := strings.TrimSpace(c.Query("ip_address")); raw != "" {
		filter.IPAddress = &raw
	}

	from, err := parseAuditTime(c.Query("from"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid from")
		return
	}
	if !from.IsZero() {
		filter.From = &from
	}
	to, err := parseAuditTime(c.Query("to"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid to")
		return
	}
	if !to.IsZero() {
		filter.To = &to
	}

	items, total, err := h.auditService.List(c.Request.Context(), filter, page, pageSize)
	if err != nil {
		handleAuditServiceError(c, err)
		return
	}

	response.Paginated(c, items, page, pageSize, total)
}

func parseAuditTime(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, nil
	}

	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts.UTC(), nil
	}
	if ts, err := time.Parse("2006-01-02", value); err == nil {
		return ts.UTC(), nil
	}

	return time.Time{}, errors.New("invalid time")
}

func handleAuditServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidAuditInput),
		errors.Is(err, service.ErrInvalidUserID):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
