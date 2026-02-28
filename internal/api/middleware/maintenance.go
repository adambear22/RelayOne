package middleware

import (
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/response"
	"nodepass-hub/internal/model"
	jwtutil "nodepass-hub/pkg/jwt"
)

var systemConfigCache atomic.Pointer[model.SystemConfig]
var maintenanceModeFlag atomic.Bool

func SetSystemConfigCache(cfg *model.SystemConfig) {
	if cfg == nil {
		systemConfigCache.Store(nil)
		maintenanceModeFlag.Store(false)
		return
	}

	copyCfg := cloneSystemConfig(cfg)
	systemConfigCache.Store(&copyCfg)
	maintenanceModeFlag.Store(copyCfg.MaintenanceMode)
}

func GetSystemConfigCache() *model.SystemConfig {
	cfg := systemConfigCache.Load()
	if cfg == nil {
		return nil
	}

	copyCfg := cloneSystemConfig(cfg)
	return &copyCfg
}

func SetMaintenanceMode(enabled bool) {
	maintenanceModeFlag.Store(enabled)
}

func IsMaintenanceMode() bool {
	return maintenanceModeFlag.Load()
}

func MaintenanceMode() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !maintenanceModeFlag.Load() {
			c.Next()
			return
		}

		if claims, ok := GetClaims(c); ok && strings.EqualFold(claims.Role, "admin") {
			c.Next()
			return
		}
		if claims, ok := resolveClaimsFromRequest(c); ok && strings.EqualFold(claims.Role, "admin") {
			c.Set(claimsContextKey, claims)
			c.Next()
			return
		}

		response.Fail(c, 503, response.ErrSystemMaintenance, "system maintenance")
		c.Abort()
	}
}

func resolveClaimsFromRequest(c *gin.Context) (*Claims, bool) {
	if c == nil {
		return nil, false
	}

	tokenString := tokenFromRequest(c)
	if tokenString == "" {
		return nil, false
	}

	publicKey, err := loadRSAPublicKey()
	if err != nil {
		return nil, false
	}

	claims, err := jwtutil.ParseAccessToken(tokenString, publicKey)
	if err != nil || claims == nil {
		return nil, false
	}

	return claims, true
}

func cloneSystemConfig(cfg *model.SystemConfig) model.SystemConfig {
	if cfg == nil {
		return model.SystemConfig{}
	}

	copyCfg := *cfg
	if len(cfg.ExternalAPIKeys) > 0 {
		copyCfg.ExternalAPIKeys = make([]model.ExternalAPIKey, 0, len(cfg.ExternalAPIKeys))
		for _, item := range cfg.ExternalAPIKeys {
			keyCopy := model.ExternalAPIKey{
				Name: item.Name,
				Key:  item.Key,
			}
			if len(item.Scopes) > 0 {
				keyCopy.Scopes = append([]string(nil), item.Scopes...)
			}
			copyCfg.ExternalAPIKeys = append(copyCfg.ExternalAPIKeys, keyCopy)
		}
	}

	return copyCfg
}
