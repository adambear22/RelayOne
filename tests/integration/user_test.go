//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"nodepass-hub/internal/model"
)

func TestAdminCreateUser(t *testing.T) {
	adminToken := loginAs(t, getEnv(t).adminUsername, adminPassword)
	username := uniqueName("create_user")

	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPost,
		"/api/v1/users/",
		map[string]interface{}{
			"username": username,
			"password": "CreateUser123!",
			"role":     "user",
			"status":   "normal",
		},
		authHeader(adminToken),
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	envelope := decodeEnvelope(t, resp)
	if envelope.Code != 0 {
		t.Fatalf("unexpected app code: %d", envelope.Code)
	}
}

func TestAdminListUsers(t *testing.T) {
	adminToken := loginAs(t, getEnv(t).adminUsername, adminPassword)

	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodGet,
		"/api/v1/users/?page=1&page_size=20",
		nil,
		authHeader(adminToken),
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestUserGetProfile(t *testing.T) {
	userToken := loginAs(t, getEnv(t).defaultUserUsername, userPassword)

	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodGet,
		"/api/v1/users/me",
		nil,
		authHeader(userToken),
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	envelope := decodeEnvelope(t, resp)
	var user model.User
	if err := json.Unmarshal(envelope.Data, &user); err != nil {
		t.Fatalf("decode profile payload: %v", err)
	}
	if user.Username != getEnv(t).defaultUserUsername {
		t.Fatalf("unexpected username: %s", user.Username)
	}
}
