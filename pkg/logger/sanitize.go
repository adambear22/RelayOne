package logger

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var sensitiveTokens = []string{
	"password",
	"token",
	"apikey",
	"api_key",
	"bottoken",
	"bot_token",
	"secret",
	"authorization",
}

func SanitizeFields(fields []zap.Field) []zap.Field {
	if len(fields) == 0 {
		return fields
	}

	sanitized := make([]zap.Field, 0, len(fields))
	for _, field := range fields {
		if isSensitiveKey(field.Key) {
			sanitized = append(sanitized, zap.String(field.Key, "***"))
			continue
		}

		encoded := encodeField(field)
		value, ok := encoded[field.Key]
		if !ok {
			sanitized = append(sanitized, field)
			continue
		}

		sanitized = append(sanitized, zap.Any(field.Key, sanitizeAny(field.Key, value)))
	}

	return sanitized
}

func sanitizeAny(parentKey string, value interface{}) interface{} {
	if isSensitiveKey(parentKey) {
		return "***"
	}

	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for k, v := range typed {
			out[k] = sanitizeAny(k, v)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeAny(parentKey, item))
		}
		return out
	case string:
		if isSensitiveKey(parentKey) {
			return "***"
		}
		return typed
	default:
		return typed
	}
}

func encodeField(field zap.Field) map[string]interface{} {
	enc := zapcore.NewMapObjectEncoder()
	field.AddTo(enc)

	out := make(map[string]interface{}, len(enc.Fields))
	for k, v := range enc.Fields {
		out[k] = v
	}
	return out
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}

	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "_", "")

	for _, token := range sensitiveTokens {
		check := strings.ReplaceAll(strings.ReplaceAll(token, "-", ""), "_", "")
		if normalized == check || strings.Contains(normalized, check) {
			return true
		}
	}

	return false
}
