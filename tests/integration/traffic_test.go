//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	cryptoutil "nodepass-hub/pkg/crypto"
)

func TestTrafficReport_Batch(t *testing.T) {
	user, userToken := createRegularUser(t)
	node := createNode(t, userToken)
	rule := createRule(t, userToken, node.ID)

	agentToken := cryptoutil.GenerateAgentHMACToken(node.ID.String(), getEnv(t).internalSecret)
	payload := map[string]interface{}{
		"records": []map[string]interface{}{
			{
				"rule_id":    rule.ID.String(),
				"bytes_in":   128,
				"bytes_out":  256,
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
				"targetHost": "example.com",
			},
		},
	}

	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPost,
		"/api/internal/traffic/batch",
		payload,
		map[string]string{
			"X-Agent-ID":    node.ID.String(),
			"X-Agent-Token": agentToken,
		},
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	userAfter := userByID(t, user.ID)
	if userAfter.TrafficUsed < 384 {
		t.Fatalf("expected traffic_used >= 384, got %d", userAfter.TrafficUsed)
	}
}

func TestMonthlyQuotaReset(t *testing.T) {
	user, _ := createRegularUser(t)
	adminToken := loginAs(t, getEnv(t).adminUsername, adminPassword)

	if _, err := getEnv(t).pool.Exec(
		t.Context(),
		`UPDATE users SET traffic_used = 1024 WHERE id = $1`,
		user.ID,
	); err != nil {
		t.Fatalf("seed traffic_used failed: %v", err)
	}

	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPost,
		fmt.Sprintf("/api/v1/traffic/reset/%s", user.ID.String()),
		nil,
		authHeader(adminToken),
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	userAfter := userByID(t, user.ID)
	if userAfter.TrafficUsed != 0 {
		t.Fatalf("expected traffic_used=0, got %d", userAfter.TrafficUsed)
	}
}
