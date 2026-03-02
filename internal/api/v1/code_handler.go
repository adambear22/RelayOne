package v1

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	inputsanitize "nodepass-hub/internal/api/sanitize"
	"nodepass-hub/internal/service"
)

type CodeHandler struct {
	codeService *service.BenefitCodeService
}

type batchGenerateCodeRequest struct {
	Count        int      `json:"count" binding:"required"`
	VIPLevel     int      `json:"vip_level" binding:"required"`
	DurationDays int      `json:"duration_days"`
	ExpiresAt    *string  `json:"expires_at"`
	ValidDays    int      `json:"valid_days"`
	CustomCodes  []string `json:"custom_codes"`
}

type batchUpdateCodeStatusRequest struct {
	IDs     []string `json:"ids" binding:"required"`
	Enabled bool     `json:"enabled"`
}

type batchDeleteCodeRequest struct {
	IDs []string `json:"ids" binding:"required"`
}

type redeemCodeRequest struct {
	Code string `json:"code" binding:"required"`
}

func NewCodeHandler(codeService *service.BenefitCodeService) *CodeHandler {
	return &CodeHandler{codeService: codeService}
}

func RegisterCodeRoutes(group *gin.RouterGroup, codeService *service.BenefitCodeService) {
	if codeService == nil {
		return
	}

	handler := NewCodeHandler(codeService)
	codes := group.Group("/codes")
	codes.Use(middleware.JWTAuth())

	codes.GET("/", handler.List)
	codes.GET("/redeem/history", handler.ListRedeemHistory)
	codes.POST("/batch-generate", middleware.AuditLog("benefit_code.batch_generate", "benefit_code"), handler.BatchGenerate)
	codes.PATCH("/status", middleware.AuditLog("benefit_code.batch_update_status", "benefit_code"), handler.BatchUpdateStatus)
	codes.DELETE("/batch", middleware.AuditLog("benefit_code.batch_delete", "benefit_code"), handler.BatchDelete)
	codes.POST(
		"/redeem",
		middleware.RateLimit("user_id", 10, time.Minute),
		middleware.AuditLog("benefit_code.redeem", "benefit_code"),
		handler.Redeem,
	)
}

// List
// @Summary List
// @Description Auto-generated endpoint documentation for List.
// @Tags code
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/codes [get]
func (h *CodeHandler) List(c *gin.Context) {
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

	filter := service.BenefitCodeListFilter{}
	if raw := strings.TrimSpace(c.Query("vip_level")); raw != "" {
		level, err := strconv.Atoi(raw)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid vip_level")
			return
		}
		filter.VIPLevel = &level
	}
	if raw := strings.TrimSpace(c.Query("is_used")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid is_used")
			return
		}
		filter.IsUsed = &value
	}
	if raw := strings.TrimSpace(c.Query("is_enabled")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid is_enabled")
			return
		}
		filter.IsEnabled = &value
	}
	if keyword := strings.TrimSpace(c.Query("keyword")); keyword != "" {
		cleaned := inputsanitize.Text(keyword)
		filter.Keyword = &cleaned
	}

	items, total, err := h.codeService.List(c.Request.Context(), page, pageSize, filter)
	if err != nil {
		handleBenefitCodeServiceError(c, err)
		return
	}

	response.Paginated(c, items, page, pageSize, total)
}

// ListRedeemHistory
// @Summary ListRedeemHistory
// @Description Auto-generated endpoint documentation for ListRedeemHistory.
// @Tags code
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/codes/redeem/history [get]
func (h *CodeHandler) ListRedeemHistory(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	page := parseIntOrDefault(c.Query("page"), 1)
	pageSize := parseIntOrDefault(c.Query("page_size"), 20)
	items, total, err := h.codeService.ListRedeemHistory(c.Request.Context(), claims.UserID, page, pageSize)
	if err != nil {
		handleBenefitCodeServiceError(c, err)
		return
	}

	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}

		var (
			usedAt    *string
			expiresAt *string
		)
		if item.UsedAt != nil {
			formatted := item.UsedAt.UTC().Format(time.RFC3339Nano)
			usedAt = &formatted
			if item.DurationDays > 0 {
				exp := item.UsedAt.UTC().AddDate(0, 0, item.DurationDays).Format(time.RFC3339Nano)
				expiresAt = &exp
			}
		}

		remark := fmt.Sprintf("通过权益码兑换：VIP Lv.%d，时长 %d 天", item.VIPLevel, item.DurationDays)
		result = append(result, gin.H{
			"id":            item.ID.String(),
			"code":          item.Code,
			"vip_level":     item.VIPLevel,
			"duration_days": item.DurationDays,
			"used_at":       usedAt,
			"expires_at":    expiresAt,
			"source":        "benefit_code",
			"remark":        remark,
		})
	}

	response.Paginated(c, result, page, pageSize, total)
}

// BatchGenerate
// @Summary BatchGenerate
// @Description Auto-generated endpoint documentation for BatchGenerate.
// @Tags code
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/codes/batch-generate [post]
func (h *CodeHandler) BatchGenerate(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req batchGenerateCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil && strings.TrimSpace(*req.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*req.ExpiresAt))
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid expires_at")
			return
		}
		expiresAt = &parsed
	}

	items, err := h.codeService.BatchGenerate(c.Request.Context(), claims.UserID, service.BatchGenerateRequest{
		Count:        req.Count,
		VIPLevel:     req.VIPLevel,
		DurationDays: req.DurationDays,
		ExpiresAt:    expiresAt,
		ValidDays:    req.ValidDays,
		CustomCodes:  inputsanitize.StringSlice(req.CustomCodes),
	})
	if err != nil {
		handleBenefitCodeServiceError(c, err)
		return
	}

	response.Success(c, items)
}

// BatchUpdateStatus
// @Summary BatchUpdateStatus
// @Description Auto-generated endpoint documentation for BatchUpdateStatus.
// @Tags code
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/codes/status [patch]
func (h *CodeHandler) BatchUpdateStatus(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req batchUpdateCodeStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if err := h.codeService.BatchUpdateStatus(c.Request.Context(), req.IDs, req.Enabled); err != nil {
		handleBenefitCodeServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"updated": len(req.IDs), "enabled": req.Enabled})
}

// BatchDelete
// @Summary BatchDelete
// @Description Auto-generated endpoint documentation for BatchDelete.
// @Tags code
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/codes/batch [delete]
func (h *CodeHandler) BatchDelete(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	var req batchDeleteCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if err := h.codeService.BatchDelete(c.Request.Context(), req.IDs); err != nil {
		handleBenefitCodeServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"deleted": len(req.IDs)})
}

func (h *CodeHandler) Redeem(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req redeemCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if err := h.codeService.Redeem(c.Request.Context(), claims.UserID, inputsanitize.Text(req.Code)); err != nil {
		handleBenefitCodeServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"redeemed": true})
}

func handleBenefitCodeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrBenefitCodeNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrCodeNotFound, "code not found")
	case errors.Is(err, service.ErrBenefitCodeUsed):
		response.Fail(c, http.StatusConflict, response.ErrCodeUsed, "code already used")
	case errors.Is(err, service.ErrBenefitCodeExpired):
		response.Fail(c, http.StatusGone, response.ErrCodeExpired, "code expired")
	case errors.Is(err, service.ErrBenefitCodeDisabled):
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "code disabled")
	case errors.Is(err, service.ErrVIPLevelNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrInternal, "vip level not found")
	case errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidVIPLevelInput),
		errors.Is(err, service.ErrInvalidBenefitCodeInput):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
