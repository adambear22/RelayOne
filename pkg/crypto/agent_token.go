package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func GenerateAgentHMACToken(agentID, secret string) string {
	cleanAgentID := strings.TrimSpace(agentID)
	cleanSecret := strings.TrimSpace(secret)
	if cleanAgentID == "" || cleanSecret == "" {
		return ""
	}

	mac := hmac.New(sha256.New, []byte(cleanSecret))
	_, _ = mac.Write([]byte(cleanAgentID))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyAgentHMACToken(agentID, token, secret string) bool {
	expected := GenerateAgentHMACToken(agentID, secret)
	if expected == "" {
		return false
	}

	provided := strings.ToLower(strings.TrimSpace(token))
	if len(provided) != len(expected) {
		return false
	}

	return hmac.Equal([]byte(provided), []byte(expected))
}
