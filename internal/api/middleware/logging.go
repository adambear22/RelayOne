package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	loggerpkg "nodepass-hub/pkg/logger"
)

const requestBodyLogLimit = 1 << 20 // 1 MiB

func RequestLogger(logger *zap.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}

	return func(c *gin.Context) {
		startedAt := time.Now()
		requestBody := snapshotRequestBody(c)

		c.Next()

		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("path", c.FullPath()),
			zap.String("raw_path", c.Request.URL.Path),
			zap.Any("query", c.Request.URL.Query()),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
			zap.Int("status", c.Writer.Status()),
			zap.Int("size", c.Writer.Size()),
			zap.Duration("latency", time.Since(startedAt)),
		}

		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			fields = append(fields, zap.String("authorization", authHeader))
		}

		if len(requestBody) > 0 {
			var payload interface{}
			if err := json.Unmarshal(requestBody, &payload); err == nil {
				fields = append(fields, zap.Any("request_body", payload))
			}
		}

		sanitized := loggerpkg.SanitizeFields(fields)
		if c.Writer.Status() >= 500 {
			logger.Error("http request completed", sanitized...)
			return
		}
		if c.Writer.Status() >= 400 {
			logger.Warn("http request completed", sanitized...)
			return
		}
		logger.Info("http request completed", sanitized...)
	}
}

func snapshotRequestBody(c *gin.Context) []byte {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return nil
	}

	raw, err := io.ReadAll(c.Request.Body)
	if err != nil || len(raw) == 0 {
		if c.Request.Body != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(nil))
		}
		return nil
	}

	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	if len(raw) <= requestBodyLogLimit {
		return raw
	}
	return raw[:requestBodyLogLimit]
}
