//go:build integration

package integration

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nodepass-hub/internal/sse"
)

func TestSSEConnect_Unauthenticated(t *testing.T) {
	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodGet,
		"/api/v1/events",
		nil,
		nil,
		nil,
	)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestSSEReceiveEvent_OnNodeStatusChange(t *testing.T) {
	user, _ := createRegularUser(t)
	session := loginSession(t, user.Username, "UserPass123!")
	if session.AccessCookie == nil {
		t.Fatal("expected access cookie")
	}

	server := httptest.NewServer(getEnv(t).router)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatalf("create sse request failed: %v", err)
	}
	req.AddCookie(session.AccessCookie)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("open sse stream failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	go func() {
		time.Sleep(200 * time.Millisecond)
		getEnv(t).sseHub.SendToUser(user.ID.String(), sse.NewEvent(sse.EventNodeStatus, map[string]interface{}{
			"node_id": "node-demo",
			"status":  "online",
		}))
	}()

	scanner := bufio.NewScanner(resp.Body)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "event: "+sse.EventNodeStatus {
			found = true
			break
		}
	}

	if err := scanner.Err(); err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("scan sse stream failed: %v", err)
	}

	if !found {
		t.Fatal("expected node status sse event")
	}
}
