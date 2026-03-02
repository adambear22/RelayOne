//go:build loadtest

package loadtest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	cryptoutil "nodepass-hub/pkg/crypto"
)

func TestWebSocket_10kConcurrentAgents(t *testing.T) {
	baseURL := os.Getenv("NODEPASS_WS_URL")
	secret := os.Getenv("NODEPASS_AGENT_HMAC_SECRET")
	if baseURL == "" || secret == "" {
		t.Skip("set NODEPASS_WS_URL and NODEPASS_AGENT_HMAC_SECRET")
	}

	total := 10000
	if raw := os.Getenv("LOADTEST_WS_AGENTS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			total = parsed
		}
	}
	if testing.Short() && total > 1000 {
		total = 1000
	}

	var connected atomic.Int64
	var failed atomic.Int64
	var wg sync.WaitGroup

	start := time.Now()
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			agentID := fmt.Sprintf("loadtest-agent-%d", id)
			wsURL := buildWSURL(baseURL, agentID, secret)
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				failed.Add(1)
				return
			}
			defer conn.Close()

			connected.Add(1)
			keepAlive(conn, 60*time.Second)
		}(i)

		if i%10 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	wg.Wait()

	t.Logf("total=%d connected=%d failed=%d duration=%s", total, connected.Load(), failed.Load(), time.Since(start))

	if failed.Load() > 0 {
		t.Fatalf("ws load test failed: %d connections failed", failed.Load())
	}
}

func buildWSURL(baseURL string, agentID string, secret string) string {
	token := cryptoutil.GenerateAgentHMACToken(agentID, secret)

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Set("agent_id", agentID)
	query.Set("token", token)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func keepAlive(conn *websocket.Conn, duration time.Duration) {
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_ = conn.WriteJSON(map[string]interface{}{
			"type": "pong",
		})

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, raw, err := conn.ReadMessage()
		if err == nil && len(raw) > 0 {
			var msg map[string]interface{}
			_ = json.Unmarshal(raw, &msg)
		}

		time.Sleep(10 * time.Second)
	}
}
