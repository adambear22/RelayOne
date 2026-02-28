package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

var (
	auditRepoMu sync.RWMutex
	auditRepo   repository.AuditRepository
)

func SetAuditRepository(repo repository.AuditRepository) {
	auditRepoMu.Lock()
	defer auditRepoMu.Unlock()
	auditRepo = repo
}

func AuditLog(action, resourceType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		repo := getAuditRepository()
		if repo == nil {
			c.Next()
			return
		}

		var body []byte
		if c.Request != nil && c.Request.Body != nil {
			body, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
		}

		c.Next()

		if c.Writer.Status() >= http.StatusBadRequest {
			return
		}

		claims, _ := GetClaims(c)
		userID := parseUserID(claims)
		resourceID := resolveResourceID(c)
		ipAddress := strPtr(c.ClientIP())
		userAgent := strPtr(c.Request.UserAgent())
		oldValue, newValue := extractAuditValues(body)

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			log := &model.AuditLog{
				UserID:       userID,
				Action:       action,
				ResourceType: strPtr(resourceType),
				ResourceID:   resourceID,
				OldValue:     oldValue,
				NewValue:     newValue,
				IPAddress:    ipAddress,
				UserAgent:    userAgent,
				CreatedAt:    time.Now().UTC(),
			}

			_ = repo.Create(ctx, log)
		}()
	}
}

func getAuditRepository() repository.AuditRepository {
	auditRepoMu.RLock()
	defer auditRepoMu.RUnlock()
	return auditRepo
}

func parseUserID(claims *Claims) *uuid.UUID {
	if claims == nil || claims.UserID == "" {
		return nil
	}

	id, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil
	}
	return &id
}

func resolveResourceID(c *gin.Context) *string {
	if id := c.Param("id"); id != "" {
		return &id
	}
	if id := c.Query("id"); id != "" {
		return &id
	}
	return nil
}

func extractAuditValues(body []byte) (map[string]interface{}, map[string]interface{}) {
	if len(body) == 0 {
		return nil, nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil
	}

	var oldValue map[string]interface{}
	if raw, ok := payload["old_value"]; ok {
		if cast, ok := raw.(map[string]interface{}); ok {
			oldValue = cast
		}
	}

	var newValue map[string]interface{}
	if raw, ok := payload["new_value"]; ok {
		if cast, ok := raw.(map[string]interface{}); ok {
			newValue = cast
		}
	}

	return oldValue, newValue
}

func strPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
