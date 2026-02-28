package v1

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/api/response"
	inputsanitize "nodepass-hub/internal/api/sanitize"
	"nodepass-hub/internal/service"
	"nodepass-hub/pkg/telegram"
)

const (
	accessTokenCookieName  = "access_token"
	refreshTokenCookieName = "refresh_token"
	accessTokenTTL         = 2 * time.Hour
	refreshTokenTTL        = 7 * 24 * time.Hour
)

type AuthHandler struct {
	authService   *service.AuthService
	systemService *service.SystemService
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

func NewAuthHandler(authService *service.AuthService, systemService *service.SystemService) *AuthHandler {
	return &AuthHandler{
		authService:   authService,
		systemService: systemService,
	}
}

func RegisterAuthRoutes(group *gin.RouterGroup, authService *service.AuthService, systemService *service.SystemService) {
	if authService == nil || systemService == nil {
		return
	}

	handler := NewAuthHandler(authService, systemService)
	auth := group.Group("/auth")
	auth.POST(
		"/login",
		middleware.RateLimit("ip", 5, time.Minute),
		middleware.RateLimitByJSONField("username", 10, time.Minute),
		handler.Login,
	)
	auth.POST("/refresh", handler.Refresh)
	auth.POST("/logout", handler.Logout)
	auth.POST("/password", middleware.JWTAuth(), handler.ChangePassword)
	auth.GET("/telegram/callback", handler.TelegramCallback)
	auth.GET("/sso", middleware.JWTAuth(), handler.SSO)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	accessToken, refreshToken, err := h.authService.Login(
		c.Request.Context(),
		inputsanitize.Text(req.Username),
		req.Password,
	)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	setSecureCookie(c, accessTokenCookieName, accessToken, int(accessTokenTTL.Seconds()))
	setSecureCookie(c, refreshTokenCookieName, refreshToken, int(refreshTokenTTL.Seconds()))

	response.Success(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// Refresh
// @Summary Refresh
// @Description Auto-generated endpoint documentation for Refresh.
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie(refreshTokenCookieName)
	if err != nil || refreshToken == "" {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	newAccessToken, newRefreshToken, err := h.authService.RefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	setSecureCookie(c, accessTokenCookieName, newAccessToken, int(accessTokenTTL.Seconds()))
	setSecureCookie(c, refreshTokenCookieName, newRefreshToken, int(refreshTokenTTL.Seconds()))

	response.Success(c, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

// Logout
// @Summary Logout
// @Description Auto-generated endpoint documentation for Logout.
// @Tags auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, _ := c.Cookie(refreshTokenCookieName)
	if err := h.authService.Logout(c.Request.Context(), refreshToken); err != nil && !errors.Is(err, service.ErrRefreshTokenInvalid) {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	clearCookie(c, accessTokenCookieName)
	clearCookie(c, refreshTokenCookieName)
	response.Success(c, gin.H{"message": "logout success"})
}

// ChangePassword
// @Summary ChangePassword
// @Description Auto-generated endpoint documentation for ChangePassword.
// @Tags auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
		return
	}

	err := h.authService.ChangePassword(c.Request.Context(), claims.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	clearCookie(c, accessTokenCookieName)
	clearCookie(c, refreshTokenCookieName)
	response.Success(c, gin.H{"message": "password changed"})
}

// TelegramCallback
// @Summary TelegramCallback
// @Description Auto-generated endpoint documentation for TelegramCallback.
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/telegram/callback [get]
func (h *AuthHandler) TelegramCallback(c *gin.Context) {
	cfg, err := h.systemService.GetConfig(c.Request.Context())
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	token := strings.TrimSpace(cfg.TelegramConfig.BotToken)
	if token == "" {
		response.Fail(c, http.StatusServiceUnavailable, response.ErrInternal, "telegram is not configured")
		return
	}

	queryMap := make(map[string]string)
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			queryMap[key] = values[0]
		}
	}
	if !telegram.VerifyWidgetHash(queryMap, token) {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "invalid telegram payload")
		return
	}

	authDate, err := telegram.ParseAuthDate(queryMap["auth_date"])
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid auth_date")
		return
	}
	if time.Since(authDate) > 24*time.Hour {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "telegram auth expired")
		return
	}

	telegramID, err := strconv.ParseInt(strings.TrimSpace(queryMap["id"]), 10, 64)
	if err != nil || telegramID == 0 {
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid telegram id")
		return
	}

	user, err := h.authService.FindByTelegramID(c.Request.Context(), telegramID)
	if err != nil {
		if !errors.Is(err, service.ErrUserNotFound) {
			response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
			return
		}

		if !cfg.RegistrationEnabled {
			response.Fail(c, http.StatusForbidden, response.ErrForbidden, "registration disabled")
			return
		}

		user, err = h.authService.CreateTelegramUser(
			c.Request.Context(),
			telegramID,
			inputsanitize.Text(queryMap["first_name"]),
			inputsanitize.Text(queryMap["username"]),
			service.TelegramRegistrationOptions{
				DefaultTrafficQuota: cfg.DefaultTrafficQuota,
				DefaultMaxRules:     cfg.DefaultMaxRules,
			},
		)
		if err != nil {
			response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "create user failed")
			return
		}
	}

	accessToken, refreshToken, err := h.authService.LoginByUserID(c.Request.Context(), user.ID.String())
	if err != nil {
		handleAuthError(c, err)
		return
	}

	setSecureCookie(c, accessTokenCookieName, accessToken, int(accessTokenTTL.Seconds()))
	setSecureCookie(c, refreshTokenCookieName, refreshToken, int(refreshTokenTTL.Seconds()))

	redirectURL := strings.TrimSpace(cfg.TelegramConfig.FrontendURL)
	if redirectURL == "" {
		redirectURL = "/"
	}
	c.Redirect(http.StatusFound, redirectURL)
}

// SSO
// @Summary SSO
// @Description Auto-generated endpoint documentation for SSO.
// @Tags auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Security ApiKeyAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 403 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/sso [get]
func (h *AuthHandler) SSO(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "unauthorized")
		return
	}

	ssoToken, err := h.authService.GenerateSSOToken(c.Request.Context(), claims.UserID)
	if err != nil {
		handleAuthError(c, err)
		return
	}

	cfg, err := h.systemService.GetConfig(c.Request.Context())
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
		return
	}

	baseURL := strings.TrimSpace(cfg.TelegramConfig.SSOBaseURL)
	if baseURL == "" {
		baseURL = "https://hub.example.com/auth/sso"
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "invalid sso base url")
		return
	}
	q := u.Query()
	q.Set("token", ssoToken)
	u.RawQuery = q.Encode()

	response.Success(c, gin.H{"url": u.String()})
}

func handleAuthError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		response.Fail(c, http.StatusUnauthorized, response.ErrPasswordWrong, "username or password incorrect")
	case errors.Is(err, service.ErrUserBanned):
		response.Fail(c, http.StatusForbidden, response.ErrUserBanned, "user banned")
	case errors.Is(err, service.ErrUserNotFound):
		response.Fail(c, http.StatusNotFound, response.ErrUserNotFound, "user not found")
	case errors.Is(err, service.ErrRefreshTokenExpired):
		response.Fail(c, http.StatusUnauthorized, response.ErrTokenExpired, "refresh token expired")
	case errors.Is(err, service.ErrRefreshTokenInvalid):
		response.Fail(c, http.StatusUnauthorized, response.ErrUnauthorized, "invalid refresh token")
	case errors.Is(err, service.ErrInvalidUserID):
		response.Fail(c, http.StatusBadRequest, response.ErrInternal, "invalid request")
	default:
		response.Fail(c, http.StatusInternalServerError, response.ErrInternal, "internal error")
	}
}

func setSecureCookie(c *gin.Context, name, value string, maxAge int) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(name, value, maxAge, "/", "", true, true)
}

func clearCookie(c *gin.Context, name string) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(name, "", -1, "/", "", true, true)
}
