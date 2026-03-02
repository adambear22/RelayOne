//go:build integration

package integration

import (
	"net/http"
	"testing"
)

func TestCreateRule_SingleMode(t *testing.T) {
	user, userToken := createRegularUser(t)
	node := createNode(t, userToken)

	rule := createRule(t, userToken, node.ID)
	if rule.ID.String() == "" {
		t.Fatal("expected rule id")
	}
	if rule.OwnerID != user.ID {
		t.Fatalf("unexpected owner id: %s", rule.OwnerID)
	}
}

func TestRuleLifecycle_CreateStartStopDelete(t *testing.T) {
	_, userToken := createRegularUser(t)
	node := createNode(t, userToken)
	setNodeOnline(t, node.ID)

	rule := createRule(t, userToken, node.ID)

	startResp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPost,
		"/api/v1/rules/"+rule.ID.String()+"/start",
		nil,
		authHeader(userToken),
		nil,
	)
	if startResp.Code != http.StatusOK {
		t.Fatalf("expected start status 200, got %d body=%s", startResp.Code, startResp.Body.String())
	}

	stopResp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPost,
		"/api/v1/rules/"+rule.ID.String()+"/stop",
		nil,
		authHeader(userToken),
		nil,
	)
	if stopResp.Code != http.StatusOK {
		t.Fatalf("expected stop status 200, got %d body=%s", stopResp.Code, stopResp.Body.String())
	}

	deleteResp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodDelete,
		"/api/v1/rules/"+rule.ID.String(),
		nil,
		authHeader(userToken),
		nil,
	)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("expected delete status 200, got %d body=%s", deleteResp.Code, deleteResp.Body.String())
	}
}
