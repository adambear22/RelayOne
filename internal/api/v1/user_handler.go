package v1

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	inputsanitize "nodepass-hub/internal/api/sanitize"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/service"
)

type UserHandler struct {
	userService *service.UserService
}

type TelegramWebhookHandler struct {
	userService         *service.UserService
	systemService       *service.SystemService
	notificationService *service.NotificationService
	logger              *zap.Logger
}

type createUserRequest struct {
	Username         string   `json:"username" binding:"required"`
	Credential       string   `json:"password" binding:"required"` // #nosec G117 -- request DTO field.
	Email            *string  `json:"email"`
	Role             string   `json:"role"`
	Status           string   `json:"status"`
	TelegramID       *int64   `json:"telegram_id"`
	TelegramUsername *string  `json:"telegram_username"`
	VIPLevel         int      `json:"vip_level"`
	VIPExpiresAt     *string  `json:"vip_expires_at"`
	TrafficQuota     int64    `json:"traffic_quota"`
	BandwidthLimit   int64    `json:"bandwidth_limit"`
	MaxRules         int      `json:"max_rules"`
	Permissions      []string `json:"permissions"`
}

type updateUserRequest struct {
	Username       *string   `json:"username"`
	Email          *string   `json:"email"`
	Role           *string   `json:"role"`
	Status         *string   `json:"status"`
	VIPLevel       *int      `json:"vip_level"`
	VIPExpiresAt   *string   `json:"vip_expires_at"`
	TrafficQuota   *int64    `json:"traffic_quota"`
	BandwidthLimit *int64    `json:"bandwidth_limit"`
	MaxRules       *int      `json:"max_rules"`
	Permissions    *[]string `json:"permissions"`
}

type statusUpdateRequest struct {
	Status string `json:"status" binding:"required"`
}

type bindTelegramRequest struct {
	TelegramID *int64  `json:"telegram_id,omitempty"`
	Username   string  `json:"username,omitempty"`
	BindCode   *string `json:"bind_code,omitempty"`
}

func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

func RegisterUserRoutes(group *gin.RouterGroup, userService *service.UserService) {
	handler := NewUserHandler(userService)
	users := group.Group("/users")
	users.Use(middleware.JWTAuth())

	users.GET("/", handler.List)
	users.POST("/", middleware.AuditLog("user.create", "user"), handler.Create)
	users.GET("/me", handler.Me)
	users.GET("/:id", handler.GetByID)
	users.PUT("/:id", middleware.AuditLog("user.update", "user"), handler.Update)
	users.PATCH("/:id/status", middleware.AuditLog("user.status_change", "user"), handler.SetStatus)
	users.POST("/:id/telegram/bind", middleware.AuditLog("user.telegram_bind", "user"), handler.BindTelegram)
	users.DELETE("/:id/telegram/bind", middleware.AuditLog("user.telegram_unbind", "user"), handler.UnbindTelegram)
}

func RegisterTelegramWebhookRoute(
	group *gin.RouterGroup,
	userService *service.UserService,
	systemService *service.SystemService,
	notificationService *service.NotificationService,
	logger *zap.Logger,
) {
	if userService == nil || systemService == nil || notificationService == nil {
		return
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	handler := &TelegramWebhookHandler{
		userService:         userService,
		systemService:       systemService,
		notificationService: notificationService,
		logger:              logger,
	}

	auth := group.Group("/auth")
	auth.POST("/telegram/webhook", handler.Webhook)
}

// List
// @Summary List
// @Description Auto-generated endpoint documentation for List.
// @Tags user
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/users [get]
func (h *UserHandler) List(c *gin.Context) {
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

	filters := make([]service.UserFilter, 0, 3)
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		filters = append(filters, service.ByStatus(model.UserStatus(status)))
	}
	if role := strings.TrimSpace(c.Query("role")); role != "" {
		filters = append(filters, service.ByRole(model.UserRole(role)))
	}
	if keyword := strings.TrimSpace(c.Query("keyword")); keyword != "" {
		filters = append(filters, service.ByKeyword(inputsanitize.Text(keyword)))
	}

	users, total, err := h.userService.List(c.Request.Context(), page, pageSize, filters...)
	if err != nil {
		handleUserServiceError(c, err)
		return
	}

	response.Paginated(c, users, page, pageSize, total)
}

// Create
// @Summary Create
// @Description Auto-generated endpoint documentation for Create.
// @Tags user
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/users [post]
func (h *UserHandler) Create(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	serviceReq := service.CreateUserRequest{
		OperatorID:       claims.UserID,
		Username:         inputsanitize.Text(req.Username),
		PasswordPlain:    req.Credential,
		Email:            inputsanitize.TextPtr(req.Email),
		Role:             model.UserRole(inputsanitize.Text(req.Role)),
		Status:           model.UserStatus(inputsanitize.Text(req.Status)),
		TelegramID:       req.TelegramID,
		TelegramUsername: inputsanitize.TextPtr(req.TelegramUsername),
		VIPLevel:         req.VIPLevel,
		TrafficQuota:     req.TrafficQuota,
		BandwidthLimit:   req.BandwidthLimit,
		MaxRules:         req.MaxRules,
		Permissions:      inputsanitize.StringSlice(req.Permissions),
	}
	if req.VIPExpiresAt != nil {
		vipExpiresAt, err := time.Parse(time.RFC3339, *req.VIPExpiresAt)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid vip_expires_at")
			return
		}
		serviceReq.VIPExpiresAt = &vipExpiresAt
	}

	user, err := h.userService.Create(c.Request.Context(), serviceReq)
	if err != nil {
		handleUserServiceError(c, err)
		return
	}

	response.Success(c, user)
}

// GetByID
// @Summary GetByID
// @Description Auto-generated endpoint documentation for GetByID.
// @Tags user
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
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) GetByID(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	targetID := c.Param("id")
	if !isAdmin(claims.Role) && claims.UserID != targetID {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	user, err := h.userService.GetByID(c.Request.Context(), targetID)
	if err != nil {
		handleUserServiceError(c, err)
		return
	}

	response.Success(c, user)
}

// Update
// @Summary Update
// @Description Auto-generated endpoint documentation for Update.
// @Tags user
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
// @Router /api/v1/users/{id} [put]
func (h *UserHandler) Update(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	targetID := c.Param("id")
	admin := isAdmin(claims.Role)
	if !admin && claims.UserID != targetID {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if !admin && hasSensitiveFields(req) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	serviceReq := service.UpdateUserRequest{
		OperatorID: claims.UserID,
		Username:   inputsanitize.TextPtr(req.Username),
		Email:      inputsanitize.TextPtr(req.Email),
	}

	if admin {
		serviceReq.VIPLevel = req.VIPLevel
		serviceReq.TrafficQuota = req.TrafficQuota
		serviceReq.BandwidthLimit = req.BandwidthLimit
		serviceReq.MaxRules = req.MaxRules
		serviceReq.Permissions = req.Permissions

		if req.Role != nil {
			role := model.UserRole(inputsanitize.Text(*req.Role))
			serviceReq.Role = &role
		}
		if req.Status != nil {
			status := model.UserStatus(inputsanitize.Text(*req.Status))
			serviceReq.Status = &status
		}
		if req.Permissions != nil {
			perms := inputsanitize.StringSlice(*req.Permissions)
			serviceReq.Permissions = &perms
		}
		if req.VIPExpiresAt != nil {
			vipExpiresAt, err := time.Parse(time.RFC3339, *req.VIPExpiresAt)
			if err != nil {
				response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid vip_expires_at")
				return
			}
			serviceReq.VIPExpiresAt = &vipExpiresAt
		}
	}

	user, err := h.userService.Update(c.Request.Context(), targetID, serviceReq)
	if err != nil {
		handleUserServiceError(c, err)
		return
	}

	response.Success(c, user)
}

// SetStatus
// @Summary SetStatus
// @Description Auto-generated endpoint documentation for SetStatus.
// @Tags user
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
// @Router /api/v1/users/{id}/status [patch]
func (h *UserHandler) SetStatus(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req statusUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	err := h.userService.SetStatus(
		c.Request.Context(),
		claims.UserID,
		c.Param("id"),
		model.UserStatus(inputsanitize.Text(req.Status)),
	)
	if err != nil {
		handleUserServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"status": req.Status})
}

// BindTelegram
// @Summary BindTelegram
// @Description Auto-generated endpoint documentation for BindTelegram.
// @Tags user
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
// @Router /api/v1/users/{id}/telegram/bind [post]
func (h *UserHandler) BindTelegram(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	targetID := c.Param("id")
	if claims.UserID != targetID {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req bindTelegramRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if req.BindCode != nil && strings.TrimSpace(*req.BindCode) != "" {
		if err := h.userService.BindTelegramByCode(c.Request.Context(), targetID, inputsanitize.Text(*req.BindCode)); err != nil {
			handleUserServiceError(c, err)
			return
		}
	} else {
		if req.TelegramID == nil || *req.TelegramID == 0 {
			response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
			return
		}
		if err := h.userService.BindTelegram(
			c.Request.Context(),
			targetID,
			*req.TelegramID,
			inputsanitize.Text(req.Username),
		); err != nil {
			handleUserServiceError(c, err)
			return
		}
	}

	response.Success(c, gin.H{"bound": true})
}

// UnbindTelegram
// @Summary UnbindTelegram
// @Description Auto-generated endpoint documentation for UnbindTelegram.
// @Tags user
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
// @Router /api/v1/users/{id}/telegram/bind [delete]
func (h *UserHandler) UnbindTelegram(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	targetID := c.Param("id")
	if claims.UserID != targetID {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	if err := h.userService.UnbindTelegram(c.Request.Context(), targetID); err != nil {
		handleUserServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"bound": false})
}

// Me
// @Summary Me
// @Description Auto-generated endpoint documentation for Me.
// @Tags user
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/users/me [get]
func (h *UserHandler) Me(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	user, err := h.userService.GetByID(c.Request.Context(), claims.UserID)
	if err != nil {
		handleUserServiceError(c, err)
		return
	}

	response.Success(c, user)
}

type telegramWebhookRequest struct {
	Message *telegramWebhookMessage `json:"message"`
}

type telegramWebhookMessage struct {
	Text string `json:"text"`
	From struct {
		ID        int64  `json:"id"`
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
	} `json:"from"`
	Chat struct {
		ID int64 `json:"id"`
	} `json:"chat"`
}

// Webhook
// @Summary Webhook
// @Description Auto-generated endpoint documentation for Webhook.
// @Tags user
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/telegram/webhook [post]
func (h *TelegramWebhookHandler) Webhook(c *gin.Context) {
	cfg, err := h.systemService.GetConfig(c.Request.Context())
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	secret := strings.TrimSpace(cfg.TelegramConfig.WebhookSecret)
	if secret == "" {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "telegram webhook secret not configured")
		return
	}

	if strings.TrimSpace(c.GetHeader("X-Telegram-Bot-Api-Secret-Token")) != secret {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req telegramWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}
	if req.Message == nil {
		response.Success(c, gin.H{"ok": true})
		return
	}

	chatID := req.Message.Chat.ID
	if chatID == 0 {
		chatID = req.Message.From.ID
	}
	if chatID == 0 {
		response.Success(c, gin.H{"ok": true})
		return
	}

	command := strings.Fields(strings.TrimSpace(req.Message.Text))
	if len(command) == 0 {
		response.Success(c, gin.H{"ok": true})
		return
	}

	switch strings.ToLower(command[0]) {
	case "/bind":
		h.handleBindCommand(c, req.Message, chatID)
	case "/unbind":
		h.handleUnbindCommand(c, req.Message, chatID)
	case "/status":
		h.handleStatusCommand(c, req.Message, chatID)
	default:
		_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID,
			"支持命令：/bind /unbind /status")
	}

	response.Success(c, gin.H{"ok": true})
}

func (h *TelegramWebhookHandler) handleBindCommand(c *gin.Context, msg *telegramWebhookMessage, chatID int64) {
	code, err := h.userService.GenerateTelegramBindCode(msg.From.ID, msg.From.Username)
	if err != nil {
		h.logger.Warn("generate telegram bind code failed", zap.Error(err))
		_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID, "生成绑定码失败，请稍后重试。")
		return
	}

	reply := fmt.Sprintf(
		"*绑定码：`%s`*\n请在平台用户设置中输入该绑定码，10分钟内有效。",
		code,
	)
	_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID, reply)
}

func (h *TelegramWebhookHandler) handleUnbindCommand(c *gin.Context, msg *telegramWebhookMessage, chatID int64) {
	user, err := h.userService.FindByTelegramID(c.Request.Context(), msg.From.ID)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID, "当前 Telegram 账号尚未绑定平台账户。")
			return
		}
		h.logger.Warn("find user by telegram id failed", zap.Error(err))
		_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID, "解绑失败，请稍后重试。")
		return
	}

	if err := h.userService.UnbindTelegram(c.Request.Context(), user.ID.String()); err != nil {
		h.logger.Warn("unbind telegram failed", zap.Error(err))
		_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID, "解绑失败，请稍后重试。")
		return
	}

	_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID, "解绑成功。")
}

func (h *TelegramWebhookHandler) handleStatusCommand(c *gin.Context, msg *telegramWebhookMessage, chatID int64) {
	user, err := h.userService.FindByTelegramID(c.Request.Context(), msg.From.ID)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID,
				"当前 Telegram 账号尚未绑定平台账户，请先使用 /bind 获取绑定码。")
			return
		}
		h.logger.Warn("query status by telegram failed", zap.Error(err))
		_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID, "查询失败，请稍后重试。")
		return
	}

	usage := fmt.Sprintf(
		"*账户状态*\n用户名：%s\n流量：%d / %d\nVIP：%d",
		user.Username,
		user.TrafficUsed,
		user.TrafficQuota,
		user.VIPLevel,
	)
	_ = h.notificationService.SendMarkdownToChat(c.Request.Context(), chatID, usage)
}

func handleUserServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrUserNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
	case errors.Is(err, service.ErrUserBanned):
		response.Fail(c, http.StatusForbidden, response.ErrUserBanned, "user banned")
	case errors.Is(err, service.ErrInvalidUserID), errors.Is(err, service.ErrInvalidUserInput):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	case errors.Is(err, service.ErrSelfBanForbidden):
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "cannot ban self")
	case errors.Is(err, service.ErrTelegramIDInUse):
		response.Fail(c, http.StatusConflict, response.ErrInternal, "telegram already bound")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}

func parseIntOrDefault(raw string, def int) int {
	if strings.TrimSpace(raw) == "" {
		return def
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return def
	}
	return value
}

func isAdmin(role string) bool {
	return strings.EqualFold(role, string(model.UserRoleAdmin))
}

func hasSensitiveFields(req updateUserRequest) bool {
	return req.Role != nil ||
		req.Status != nil ||
		req.VIPLevel != nil ||
		req.VIPExpiresAt != nil ||
		req.TrafficQuota != nil ||
		req.BandwidthLimit != nil ||
		req.MaxRules != nil ||
		req.Permissions != nil
}
