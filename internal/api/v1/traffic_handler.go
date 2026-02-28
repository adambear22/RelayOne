package v1

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/service"
)

type TrafficHandler struct {
	trafficService service.TrafficService
	ruleService    *service.RuleService
}

func NewTrafficHandler(trafficService service.TrafficService, ruleService *service.RuleService) *TrafficHandler {
	return &TrafficHandler{
		trafficService: trafficService,
		ruleService:    ruleService,
	}
}

func RegisterTrafficRoutes(group *gin.RouterGroup, trafficService service.TrafficService, ruleService *service.RuleService) {
	handler := NewTrafficHandler(trafficService, ruleService)
	traffic := group.Group("/traffic")
	traffic.Use(middleware.JWTAuth())

	traffic.GET("/stats", handler.QueryStats)
	traffic.GET("/daily", handler.QueryDaily)
	traffic.GET("/monthly", handler.QueryMonthly)
	traffic.GET("/rules/:id", handler.QueryRuleStats)
	traffic.GET("/overview", handler.Overview)
	traffic.POST("/reset/:userID", handler.ResetUserQuota)
	traffic.POST("/sync", handler.BatchSyncQuota)
}

// QueryStats
// @Summary QueryStats
// @Description Auto-generated endpoint documentation for QueryStats.
// @Tags traffic
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/traffic/stats [get]
func (h *TrafficHandler) QueryStats(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	granularity := strings.TrimSpace(c.DefaultQuery("granularity", "hour"))
	from, err := parseTrafficTime(c.Query("from"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid from")
		return
	}
	to, err := parseTrafficTime(c.Query("to"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid to")
		return
	}
	if from.IsZero() {
		from = time.Now().UTC().Add(-24 * time.Hour)
	}
	if to.IsZero() {
		to = time.Now().UTC()
	}

	stats, err := h.trafficService.QueryStats(c.Request.Context(), claims.UserID, granularity, from, to)
	if err != nil {
		handleTrafficServiceError(c, err)
		return
	}

	response.Success(c, stats)
}

// QueryDaily
// @Summary QueryDaily
// @Description Auto-generated endpoint documentation for QueryDaily.
// @Tags traffic
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/traffic/daily [get]
func (h *TrafficHandler) QueryDaily(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	days := parseIntOrDefault(c.DefaultQuery("days", "30"), 30)
	stats, err := h.trafficService.QueryUserDailyStats(c.Request.Context(), claims.UserID, days)
	if err != nil {
		handleTrafficServiceError(c, err)
		return
	}

	response.Success(c, stats)
}

// QueryMonthly
// @Summary QueryMonthly
// @Description Auto-generated endpoint documentation for QueryMonthly.
// @Tags traffic
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/traffic/monthly [get]
func (h *TrafficHandler) QueryMonthly(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	months := parseIntOrDefault(c.DefaultQuery("months", "12"), 12)
	stats, err := h.trafficService.QueryUserMonthlyStats(c.Request.Context(), claims.UserID, months)
	if err != nil {
		handleTrafficServiceError(c, err)
		return
	}

	response.Success(c, stats)
}

// QueryRuleStats
// @Summary QueryRuleStats
// @Description Auto-generated endpoint documentation for QueryRuleStats.
// @Tags traffic
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
// @Router /api/v1/traffic/rules/{id} [get]
func (h *TrafficHandler) QueryRuleStats(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	ruleID := strings.TrimSpace(c.Param("id"))
	if ruleID == "" {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	if !isAdmin(claims.Role) {
		if h.ruleService == nil {
			response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
			return
		}

		rule, err := h.ruleService.GetByID(c.Request.Context(), ruleID)
		if err != nil {
			handleTrafficServiceError(c, err)
			return
		}
		if rule.OwnerID.String() != claims.UserID {
			response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
			return
		}
	}

	from, err := parseTrafficTime(c.Query("from"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid from")
		return
	}
	to, err := parseTrafficTime(c.Query("to"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid to")
		return
	}

	points, err := h.trafficService.QueryRuleStats(c.Request.Context(), ruleID, from, to)
	if err != nil {
		handleTrafficServiceError(c, err)
		return
	}

	response.Success(c, points)
}

// Overview
// @Summary Overview
// @Description Auto-generated endpoint documentation for Overview.
// @Tags traffic
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/traffic/overview [get]
func (h *TrafficHandler) Overview(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	overview, err := h.trafficService.AdminOverview(c.Request.Context())
	if err != nil {
		handleTrafficServiceError(c, err)
		return
	}

	response.Success(c, overview)
}

// ResetUserQuota
// @Summary ResetUserQuota
// @Description Auto-generated endpoint documentation for ResetUserQuota.
// @Tags traffic
// @Accept json
// @Produce json
// @Param userID path string true "userID"
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/traffic/reset/{userID} [post]
func (h *TrafficHandler) ResetUserQuota(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !isAdmin(claims.Role) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	if err := h.trafficService.ResetUserQuota(c.Request.Context(), c.Param("userID")); err != nil {
		handleTrafficServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"reset": true})
}

// BatchSyncQuota
// @Summary BatchSyncQuota
// @Description Auto-generated endpoint documentation for BatchSyncQuota.
// @Tags traffic
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/traffic/sync [post]
func (h *TrafficHandler) BatchSyncQuota(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}
	if !strings.EqualFold(claims.Role, string(model.UserRoleAdmin)) {
		response.Fail(c, http.StatusForbidden, response.ErrForbidden, "forbidden")
		return
	}

	if err := h.trafficService.BatchSyncQuota(c.Request.Context()); err != nil {
		handleTrafficServiceError(c, err)
		return
	}

	response.Success(c, gin.H{"synced": true})
}

func parseTrafficTime(raw string) (time.Time, error) {
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

	return time.Time{}, errors.New("invalid time format")
}

func handleTrafficServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidTrafficInput),
		errors.Is(err, service.ErrInvalidRuleID):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	case errors.Is(err, service.ErrUserNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
	case errors.Is(err, service.ErrRuleNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrRuleNotFound, "rule not found")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}
