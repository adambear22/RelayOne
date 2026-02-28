package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"nodepass-hub/internal/api/response"
)

type slidingWindowCounter struct {
	mu         sync.Mutex
	timestamps []int64
	count      atomic.Int64
}

var rateLimiterStore sync.Map

func RateLimit(key string, limit int, window time.Duration) gin.HandlerFunc {
	return rateLimitWithResolver(limit, window, func(c *gin.Context) string {
		return resolveRateLimitKey(c, key)
	})
}

func RateLimitByJSONField(field string, limit int, window time.Duration) gin.HandlerFunc {
	field = strings.TrimSpace(field)
	return rateLimitWithResolver(limit, window, func(c *gin.Context) string {
		if field == "" {
			return ""
		}
		bodyValue := extractJSONField(c, field)
		if bodyValue == "" {
			return "json:" + field + ":missing:" + c.ClientIP()
		}
		return "json:" + field + ":" + strings.ToLower(bodyValue)
	})
}

func RateLimitByHeader(headerName string, limit int, window time.Duration) gin.HandlerFunc {
	headerName = strings.TrimSpace(headerName)
	return rateLimitWithResolver(limit, window, func(c *gin.Context) string {
		if headerName == "" {
			return ""
		}
		value := strings.TrimSpace(c.GetHeader(headerName))
		if value == "" {
			return ""
		}
		return "header:" + strings.ToLower(headerName) + ":" + strings.ToLower(value)
	})
}

func rateLimitWithResolver(limit int, window time.Duration, keyResolver func(c *gin.Context) string) gin.HandlerFunc {
	if limit <= 0 {
		limit = 60
	}
	if window <= 0 {
		window = time.Minute
	}

	return func(c *gin.Context) {
		rawKey := ""
		if keyResolver != nil {
			rawKey = keyResolver(c)
		}
		if rawKey == "" {
			rawKey = "global"
		}

		entryAny, _ := rateLimiterStore.LoadOrStore(rawKey, &slidingWindowCounter{
			timestamps: make([]int64, 0, limit),
		})
		entry := entryAny.(*slidingWindowCounter)

		now := time.Now().UnixNano()
		cutoff := now - window.Nanoseconds()

		entry.mu.Lock()
		next := entry.timestamps[:0]
		for _, ts := range entry.timestamps {
			if ts > cutoff {
				next = append(next, ts)
			}
		}
		entry.timestamps = next

		if len(entry.timestamps) >= limit {
			entry.count.Store(int64(len(entry.timestamps)))
			entry.mu.Unlock()
			response.Fail(c, 429, response.ErrInternal, "too many requests")
			c.Abort()
			return
		}

		entry.timestamps = append(entry.timestamps, now)
		entry.count.Store(int64(len(entry.timestamps)))
		entry.mu.Unlock()

		c.Next()
	}
}

func extractJSONField(c *gin.Context, field string) string {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return ""
	}

	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return ""
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))

	if len(raw) == 0 {
		return ""
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}

	value, ok := payload[field]
	if !ok || value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return strings.TrimSpace(toString(v))
	}
}

func toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return strings.TrimSpace(toJSONString(v))
	}
}

func toJSONString(value interface{}) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(raw)
}

func resolveRateLimitKey(c *gin.Context, keyTemplate string) string {
	userID := ""
	if claims, ok := GetClaims(c); ok {
		userID = claims.UserID
	}

	if keyTemplate == "" {
		keyTemplate = "ip"
	}

	switch keyTemplate {
	case "ip":
		return "ip:" + c.ClientIP()
	case "user_id":
		if userID == "" {
			return "user_id:anonymous:" + c.ClientIP()
		}
		return "user_id:" + userID
	default:
		replaced := strings.ReplaceAll(keyTemplate, "{ip}", c.ClientIP())
		replaced = strings.ReplaceAll(replaced, "{user_id}", userID)
		return replaced
	}
}
