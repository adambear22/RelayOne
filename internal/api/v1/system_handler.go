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
	systemlog "nodepass-hub/pkg/logger"
)

type SystemHandler struct {
	systemService *service.SystemService
	logStore      *systemlog.SystemLogStore
}

type updateSystemConfigRequest struct {
	SiteName            *string                 `json:"site_name"`
	SupportEmail        *string                 `json:"support_email"`
	MaintenanceMode     *bool                   `json:"maintenance_mode"`
	RegistrationEnabled *bool                   `json:"registration_enabled"`
	DefaultTrafficQuota *int64                  `json:"default_traffic_quota"`
	DefaultMaxRules     *int                    `json:"default_max_rules"`
	TelegramConfig      *model.TelegramConfig   `json:"telegram_config"`
	ExternalAPIKeys     *[]model.ExternalAPIKey `json:"external_api_keys"`
}

func NewSystemHandler(systemService *service.SystemService, logStore *systemlog.SystemLogStore) *SystemHandler {
	return &SystemHandler{
		systemService: systemService,
		logStore:      logStore,
	}
}

func RegisterSystemRoutes(
	group *gin.RouterGroup,
	systemService *service.SystemService,
	logStore *systemlog.SystemLogStore,
) {
	if systemService == nil {
		return
	}

	handler := NewSystemHandler(systemService, logStore)
	system := group.Group("/system")
	system.GET("/config", handler.GetConfig)
	system.PUT("/config", middleware.JWTAuth(), handler.UpdateConfig)
	system.GET("/logs", middleware.JWTAuth(), handler.QueryLogs)
}

// GetConfig
// @Summary GetConfig
// @Description Auto-generated endpoint documentation for GetConfig.
// @Tags system
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/system/config [get]
func (h *SystemHandler) GetConfig(c *gin.Context) {
	cfg, err := h.systemService.GetConfig(c.Request.Context())
	if err != nil {
		handleSystemServiceError(c, err)
		return
	}
	response.Success(c, cfg)
}

// UpdateConfig
// @Summary UpdateConfig
// @Description Auto-generated endpoint documentation for UpdateConfig.
// @Tags system
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/system/config [put]
func (h *SystemHandler) UpdateConfig(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req updateSystemConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	cleanTelegram := sanitizeTelegramConfig(req.TelegramConfig)
	cleanExternalKeys := sanitizeExternalAPIKeys(req.ExternalAPIKeys)

	err := h.systemService.UpdateConfig(c.Request.Context(), claims.UserID, service.UpdateSystemConfigRequest{
		SiteName:            inputsanitize.TextPtr(req.SiteName),
		SupportEmail:        inputsanitize.TextPtr(req.SupportEmail),
		MaintenanceMode:     req.MaintenanceMode,
		RegistrationEnabled: req.RegistrationEnabled,
		DefaultTrafficQuota: req.DefaultTrafficQuota,
		DefaultMaxRules:     req.DefaultMaxRules,
		TelegramConfig:      cleanTelegram,
		ExternalAPIKeys:     cleanExternalKeys,
	})
	if err != nil {
		handleSystemServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"updated": true})
}

// QueryLogs
// @Summary QueryLogs
// @Description Auto-generated endpoint documentation for QueryLogs.
// @Tags system
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/system/logs [get]
func (h *SystemHandler) QueryLogs(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}
	if h.logStore == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "log service unavailable")
		return
	}

	page := parseIntOrDefault(c.Query("page"), 1)
	pageSize := parseIntOrDefault(c.Query("page_size"), 20)
	level := strings.TrimSpace(c.Query("level"))
	keyword := strings.TrimSpace(c.Query("keyword"))

	from, err := parseSystemLogTime(c.Query("from"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid from")
		return
	}
	to, err := parseSystemLogTime(c.Query("to"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid to")
		return
	}

	items, total := h.logStore.QueryLogs(level, from, to, keyword, page, pageSize)
	response.Paginated(c, items, page, pageSize, total)
}

func parseSystemLogTime(raw string) (time.Time, error) {
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

func handleSystemServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidSystemConfigInput),
		errors.Is(err, service.ErrInvalidUserID):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}

func sanitizeTelegramConfig(cfg *model.TelegramConfig) *model.TelegramConfig {
	if cfg == nil {
		return nil
	}

	cleaned := *cfg
	cleaned.BotToken = inputsanitize.Text(cleaned.BotToken)
	cleaned.BotUsername = inputsanitize.Text(cleaned.BotUsername)
	cleaned.WebhookURL = inputsanitize.Text(cleaned.WebhookURL)
	cleaned.WebhookSecret = inputsanitize.Text(cleaned.WebhookSecret)
	cleaned.FrontendURL = inputsanitize.Text(cleaned.FrontendURL)
	cleaned.SSOBaseURL = inputsanitize.Text(cleaned.SSOBaseURL)
	return &cleaned
}

func sanitizeExternalAPIKeys(keys *[]model.ExternalAPIKey) *[]model.ExternalAPIKey {
	if keys == nil {
		return nil
	}

	values := make([]model.ExternalAPIKey, 0, len(*keys))
	for _, item := range *keys {
		values = append(values, model.ExternalAPIKey{
			Name:   inputsanitize.Text(item.Name),
			Key:    item.Key,
			Scopes: inputsanitize.StringSlice(item.Scopes),
		})
	}

	return &values
}
