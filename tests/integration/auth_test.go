//go:build integration

package integration

import (
	"net/http"
	"testing"
)

func TestLogin_Success(t *testing.T) {
	session := loginSession(t, getEnv(t).defaultUserUsername, userPassword)
	if session.AccessToken == "" {
		t.Fatal("expected access token")
	}
	if session.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}
	if session.AccessCookie == nil || session.AccessCookie.Value == "" {
		t.Fatal("expected access token cookie")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPost,
		"/api/v1/auth/login",
		map[string]interface{}{
			"username": getEnv(t).defaultUserUsername,
			"password": "wrong-password",
		},
		nil,
		nil,
	)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.Code)
	}
}

func TestLogout_Success(t *testing.T) {
	session := loginSession(t, getEnv(t).defaultUserUsername, userPassword)

	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPost,
		"/api/v1/auth/logout",
		nil,
		nil,
		session.AllCookies,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", resp.Code, resp.Body.String())
	}
}
