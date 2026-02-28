package externalapi

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/service"
)

const (
	externalScopeUsersRead       = "external.users.read"
	externalScopeTrafficAdjust   = "external.users.traffic.adjust"
	externalScopeVIPAdjust       = "external.users.vip.adjust"
	externalScopeBandwidthAdjust = "external.users.bandwidth.adjust"
)

type ExternalHandler struct {
	pool        *pgxpool.Pool
	userService *service.UserService
	vipService  *service.VIPService
	ruleService *service.RuleService
	auditRepo   repository.AuditRepository
	logger      *zap.Logger
}

type adjustTrafficRequest struct {
	Op    string `json:"op" binding:"required"`
	Bytes int64  `json:"bytes" binding:"required"`
}

type adjustVIPRequest struct {
	Op   string `json:"op" binding:"required"`
	Days int    `json:"days" binding:"required"`
}

type adjustBandwidthRequest struct {
	BPS int64 `json:"bps" binding:"required"`
}

func NewExternalHandler(
	pool *pgxpool.Pool,
	userService *service.UserService,
	vipService *service.VIPService,
	ruleService *service.RuleService,
	auditRepo repository.AuditRepository,
	logger *zap.Logger,
) *ExternalHandler {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &ExternalHandler{
		pool:        pool,
		userService: userService,
		vipService:  vipService,
		ruleService: ruleService,
		auditRepo:   auditRepo,
		logger:      logger,
	}
}

func RegisterRoutes(
	router gin.IRoutes,
	pool *pgxpool.Pool,
	userService *service.UserService,
	vipService *service.VIPService,
	ruleService *service.RuleService,
	auditRepo repository.AuditRepository,
	logger *zap.Logger,
) {
	if router == nil || pool == nil || userService == nil {
		return
	}

	handler := NewExternalHandler(pool, userService, vipService, ruleService, auditRepo, logger)
	auth := middleware.APIKeyAuth()
	router.GET(
		"/api/external/users/:identifier",
		auth,
		middleware.RequireAPIKeyScope(externalScopeUsersRead),
		handler.GetUser,
	)
	router.POST(
		"/api/external/users/:id/traffic",
		auth,
		middleware.RequireAPIKeyScope(externalScopeTrafficAdjust),
		handler.AdjustTraffic,
	)
	router.POST(
		"/api/external/users/:id/vip",
		auth,
		middleware.RequireAPIKeyScope(externalScopeVIPAdjust),
		handler.AdjustVIP,
	)
	router.POST(
		"/api/external/users/:id/bandwidth",
		auth,
		middleware.RequireAPIKeyScope(externalScopeBandwidthAdjust),
		handler.AdjustBandwidth,
	)
}

func (h *ExternalHandler) GetUser(c *gin.Context) {
	identifier := strings.TrimSpace(c.Param("identifier"))
	if identifier == "" {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	user, err := h.findUserByIdentifier(c.Request.Context(), identifier)
	if err != nil {
		handleExternalError(c, err)
		return
	}

	response.Success(c, buildExternalUserResponse(user))
}

func (h *ExternalHandler) AdjustTraffic(c *gin.Context) {
	if h.pool == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "service unavailable")
		return
	}

	userID, err := parseUserIDParam(c.Param("id"))
	if err != nil {
		handleExternalError(c, err)
		return
	}

	var req adjustTrafficRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	op := strings.ToLower(strings.TrimSpace(req.Op))
	if op != "add" && op != "set" {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}
	if req.Bytes < 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	tx, err := h.pool.BeginTx(c.Request.Context(), pgx.TxOptions{})
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}
	defer tx.Rollback(c.Request.Context()) //nolint:errcheck

	var oldQuota int64
	if err := tx.QueryRow(c.Request.Context(), `SELECT traffic_quota FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&oldQuota); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
			return
		}
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	newQuota := req.Bytes
	if op == "add" {
		value, overflow := safeAddInt64(oldQuota, req.Bytes)
		if overflow {
			response.Fail(c, http.StatusBadRequest, response.ErrInternal, "quota overflow")
			return
		}
		newQuota = value
	}

	if _, err := tx.Exec(
		c.Request.Context(),
		`UPDATE users SET traffic_quota = $2, updated_at = NOW() WHERE id = $1`,
		userID,
		newQuota,
	); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	h.writeAudit(
		c,
		"external.traffic_adjust",
		userID.String(),
		map[string]interface{}{"traffic_quota": oldQuota},
		map[string]interface{}{"op": op, "bytes": req.Bytes, "traffic_quota": newQuota},
	)

	response.Success(c, gin.H{
		"user_id":       userID.String(),
		"traffic_quota": newQuota,
	})
}

func (h *ExternalHandler) AdjustVIP(c *gin.Context) {
	if h.pool == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "service unavailable")
		return
	}

	userID, err := parseUserIDParam(c.Param("id"))
	if err != nil {
		handleExternalError(c, err)
		return
	}

	var req adjustVIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	op := strings.ToLower(strings.TrimSpace(req.Op))
	if (op != "extend" && op != "set") || req.Days < 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	now := time.Now().UTC()
	tx, err := h.pool.BeginTx(c.Request.Context(), pgx.TxOptions{})
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}
	defer tx.Rollback(c.Request.Context()) //nolint:errcheck

	var vipLevel int
	var oldExpiresAt *time.Time
	var oldTrafficQuota int64
	var oldMaxRules int
	if err := tx.QueryRow(
		c.Request.Context(),
		`SELECT vip_level, vip_expires_at, traffic_quota, max_rules FROM users WHERE id = $1 FOR UPDATE`,
		userID,
	).Scan(&vipLevel, &oldExpiresAt, &oldTrafficQuota, &oldMaxRules); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
			return
		}
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	newExpiresAt := now.Add(time.Duration(req.Days) * 24 * time.Hour)
	if op == "extend" {
		base := now
		if oldExpiresAt != nil && oldExpiresAt.After(now) {
			base = oldExpiresAt.UTC()
		}
		newExpiresAt = base.Add(time.Duration(req.Days) * 24 * time.Hour)
	}

	var levelQuota int64
	var levelMaxRules int
	if h.vipService != nil {
		level, levelErr := h.vipService.GetLevel(c.Request.Context(), vipLevel)
		if levelErr != nil {
			handleExternalError(c, levelErr)
			return
		}
		levelQuota = level.TrafficQuota
		levelMaxRules = level.MaxRules
	} else {
		if err := tx.QueryRow(
			c.Request.Context(),
			`SELECT traffic_quota, max_rules FROM vip_levels WHERE level = $1`,
			vipLevel,
		).Scan(&levelQuota, &levelMaxRules); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				response.Fail(c, http.StatusBadRequest, response.ErrInternal, "vip level not configured")
				return
			}
			response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
			return
		}
	}

	if _, err := tx.Exec(
		c.Request.Context(),
		`UPDATE users
		    SET vip_expires_at = $2,
		        traffic_quota = $3,
		        max_rules = $4,
		        updated_at = NOW()
		  WHERE id = $1`,
		userID,
		newExpiresAt,
		levelQuota,
		levelMaxRules,
	); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	h.writeAudit(
		c,
		"external.vip_adjust",
		userID.String(),
		map[string]interface{}{
			"vip_expires_at": oldExpiresAt,
			"traffic_quota":  oldTrafficQuota,
			"max_rules":      oldMaxRules,
		},
		map[string]interface{}{
			"op":             op,
			"days":           req.Days,
			"vip_expires_at": newExpiresAt,
			"traffic_quota":  levelQuota,
			"max_rules":      levelMaxRules,
		},
	)

	response.Success(c, gin.H{
		"user_id":        userID.String(),
		"vip_expires_at": newExpiresAt,
		"traffic_quota":  levelQuota,
		"max_rules":      levelMaxRules,
	})
}

func (h *ExternalHandler) AdjustBandwidth(c *gin.Context) {
	if h.pool == nil {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "service unavailable")
		return
	}

	userID, err := parseUserIDParam(c.Param("id"))
	if err != nil {
		handleExternalError(c, err)
		return
	}

	var req adjustBandwidthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}
	if req.BPS < 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	tx, err := h.pool.BeginTx(c.Request.Context(), pgx.TxOptions{})
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}
	defer tx.Rollback(c.Request.Context()) //nolint:errcheck

	var oldBPS int64
	if err := tx.QueryRow(c.Request.Context(), `SELECT bandwidth_limit FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&oldBPS); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
			return
		}
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	if _, err := tx.Exec(
		c.Request.Context(),
		`UPDATE users SET bandwidth_limit = $2, updated_at = NOW() WHERE id = $1`,
		userID,
		req.BPS,
	); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	h.writeAudit(
		c,
		"external.bandwidth_adjust",
		userID.String(),
		map[string]interface{}{"bandwidth_limit": oldBPS},
		map[string]interface{}{"bandwidth_limit": req.BPS},
	)

	syncErr := error(nil)
	if h.ruleService != nil {
		syncErr = h.ruleService.SyncUserRunningRules(c.Request.Context(), userID.String())
		if syncErr != nil {
			h.logger.Warn("sync user running rules after bandwidth adjust failed",
				zap.String("user_id", userID.String()),
				zap.Error(syncErr),
			)
		}
	}

	if syncErr != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "bandwidth updated but rule sync failed")
		return
	}

	response.Success(c, gin.H{
		"user_id":         userID.String(),
		"bandwidth_limit": req.BPS,
		"synced":          true,
	})
}

func (h *ExternalHandler) findUserByIdentifier(ctx context.Context, identifier string) (*model.User, error) {
	if id, err := strconv.ParseInt(identifier, 10, 64); err == nil {
		return h.userService.FindByTelegramID(ctx, id)
	}
	return h.userService.FindByUsername(ctx, identifier)
}

func buildExternalUserResponse(user *model.User) gin.H {
	if user == nil {
		return gin.H{}
	}

	responseData := gin.H{
		"id":              user.ID.String(),
		"username":        user.Username,
		"email":           maskEmail(pointerString(user.Email)),
		"role":            user.Role,
		"status":          user.Status,
		"vip_level":       user.VIPLevel,
		"vip_expires_at":  user.VIPExpiresAt,
		"traffic_quota":   user.TrafficQuota,
		"traffic_used":    user.TrafficUsed,
		"bandwidth_limit": user.BandwidthLimit,
		"max_rules":       user.MaxRules,
		"permissions":     user.Permissions,
		"created_at":      user.CreatedAt,
		"updated_at":      user.UpdatedAt,
	}

	if user.TelegramID != nil {
		responseData["telegram_id"] = maskTelegramID(*user.TelegramID)
	}
	if user.TelegramUsername != nil {
		responseData["telegram_username"] = *user.TelegramUsername
	}

	return responseData
}

func parseUserIDParam(raw string) (uuid.UUID, error) {
	userID, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return uuid.Nil, service.ErrInvalidUserID
	}
	return userID, nil
}

func maskEmail(email string) string {
	value := strings.TrimSpace(email)
	if value == "" {
		return ""
	}

	parts := strings.Split(value, "@")
	if len(parts) != 2 {
		return "***"
	}

	name := parts[0]
	domain := parts[1]
	if name == "" {
		return "***@" + domain
	}
	if len(name) == 1 {
		return name + "***@" + domain
	}
	return name[:1] + "***@" + domain
}

func maskTelegramID(telegramID int64) string {
	value := strconv.FormatInt(telegramID, 10)
	if len(value) <= 4 {
		return "****" + value
	}
	return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
}

func safeAddInt64(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, true
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, true
	}
	return a + b, false
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (h *ExternalHandler) writeAudit(
	c *gin.Context,
	action string,
	resourceID string,
	oldValue map[string]interface{},
	newValue map[string]interface{},
) {
	if h.auditRepo == nil {
		return
	}

	apiKeyName := ""
	if principal, ok := middleware.GetAPIKeyPrincipal(c); ok {
		apiKeyName = principal.Name
	}
	if apiKeyName != "" {
		newValue = mergeAuditValue(newValue, map[string]interface{}{"api_key": apiKeyName})
	}

	var ipAddress *string
	if ip := net.ParseIP(c.ClientIP()); ip != nil {
		ipString := ip.String()
		ipAddress = &ipString
	}

	userAgent := strings.TrimSpace(c.GetHeader("User-Agent"))
	if userAgent == "" {
		userAgent = strings.TrimSpace(c.Request.UserAgent())
	}
	if len(userAgent) > 1024 {
		userAgent = userAgent[:1024]
	}

	var userAgentPtr *string
	if userAgent != "" {
		userAgentPtr = &userAgent
	}

	_ = h.auditRepo.Create(context.Background(), &model.AuditLog{
		Action:       action,
		ResourceType: strPtr("user"),
		ResourceID:   &resourceID,
		OldValue:     oldValue,
		NewValue:     newValue,
		IPAddress:    ipAddress,
		UserAgent:    userAgentPtr,
		CreatedAt:    time.Now().UTC(),
	})
}

func mergeAuditValue(base map[string]interface{}, extras map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{}, len(base)+len(extras))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extras {
		merged[key] = value
	}
	return merged
}

func strPtr(value string) *string {
	return &value
}

func handleExternalError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidUserInput),
		errors.Is(err, service.ErrInvalidVIPLevelInput):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	case errors.Is(err, service.ErrUserNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
	case errors.Is(err, service.ErrVIPLevelNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "vip level not found")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
