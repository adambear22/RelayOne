package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"nodepass-hub/internal/sse"
)

func BenchmarkAPI_Login(b *testing.B) {
	baseURL := strings.TrimRight(os.Getenv("NODEPASS_BENCH_BASE_URL"), "/")
	username := os.Getenv("NODEPASS_BENCH_USERNAME")
	password := os.Getenv("NODEPASS_BENCH_PASSWORD")
	if baseURL == "" || username == "" || password == "" {
		b.Skip("set NODEPASS_BENCH_BASE_URL/NODEPASS_BENCH_USERNAME/NODEPASS_BENCH_PASSWORD")
	}

	body := map[string]string{
		"username": username,
		"password": password,
	}
	raw, _ := json.Marshal(body)
	client := &http.Client{Timeout: 10 * time.Second}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// #nosec G107,G704 -- benchmark target URL is intentionally configurable.
		req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/login", bytes.NewReader(raw))
		if err != nil {
			b.Fatalf("new request failed: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		// #nosec G107,G704 -- benchmark target URL is intentionally configurable.
		resp, err := client.Do(req)
		if err != nil {
			b.Fatalf("request failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("unexpected status: %d", resp.StatusCode)
		}
	}
}

func BenchmarkAPI_ListRules(b *testing.B) {
	baseURL := strings.TrimRight(os.Getenv("NODEPASS_BENCH_BASE_URL"), "/")
	token := os.Getenv("NODEPASS_BENCH_TOKEN")
	if baseURL == "" || token == "" {
		b.Skip("set NODEPASS_BENCH_BASE_URL/NODEPASS_BENCH_TOKEN")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	url := baseURL + "/api/v1/rules/?page=1&page_size=20"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// #nosec G107,G704 -- benchmark target URL is intentionally configurable.
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			b.Fatalf("new request failed: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		// #nosec G107,G704 -- benchmark target URL is intentionally configurable.
		resp, err := client.Do(req)
		if err != nil {
			b.Fatalf("request failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("unexpected status: %d", resp.StatusCode)
		}
	}
}

func BenchmarkAPI_TrafficReport(b *testing.B) {
	baseURL := strings.TrimRight(os.Getenv("NODEPASS_BENCH_BASE_URL"), "/")
	agentID := os.Getenv("NODEPASS_BENCH_AGENT_ID")
	agentToken := os.Getenv("NODEPASS_BENCH_AGENT_TOKEN")
	ruleID := os.Getenv("NODEPASS_BENCH_RULE_ID")
	if baseURL == "" || agentID == "" || agentToken == "" || ruleID == "" {
		b.Skip("set NODEPASS_BENCH_BASE_URL/NODEPASS_BENCH_AGENT_ID/NODEPASS_BENCH_AGENT_TOKEN/NODEPASS_BENCH_RULE_ID")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	payload := map[string]interface{}{
		"rule_id":   ruleID,
		"bytes_in":  128,
		"bytes_out": 256,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := postJSON(client, baseURL+"/api/internal/traffic/report", payload, map[string]string{
			"X-Agent-ID":    agentID,
			"X-Agent-Token": agentToken,
		}); err != nil {
			b.Fatalf("traffic report failed: %v", err)
		}
	}
}

func BenchmarkAPI_BatchTrafficReport100(b *testing.B) {
	baseURL := strings.TrimRight(os.Getenv("NODEPASS_BENCH_BASE_URL"), "/")
	agentID := os.Getenv("NODEPASS_BENCH_AGENT_ID")
	agentToken := os.Getenv("NODEPASS_BENCH_AGENT_TOKEN")
	ruleID := os.Getenv("NODEPASS_BENCH_RULE_ID")
	if baseURL == "" || agentID == "" || agentToken == "" || ruleID == "" {
		b.Skip("set NODEPASS_BENCH_BASE_URL/NODEPASS_BENCH_AGENT_ID/NODEPASS_BENCH_AGENT_TOKEN/NODEPASS_BENCH_RULE_ID")
	}

	records := make([]map[string]interface{}, 0, 100)
	for i := 0; i < 100; i++ {
		records = append(records, map[string]interface{}{
			"rule_id":   ruleID,
			"bytes_in":  64,
			"bytes_out": 64,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}

	client := &http.Client{Timeout: 10 * time.Second}
	payload := map[string]interface{}{
		"records": records,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := postJSON(client, baseURL+"/api/internal/traffic/batch", payload, map[string]string{
			"X-Agent-ID":    agentID,
			"X-Agent-Token": agentToken,
		}); err != nil {
			b.Fatalf("traffic batch failed: %v", err)
		}
	}
}

func BenchmarkSSE_PublishToAll_1000clients(b *testing.B) {
	hub := sse.NewHub(nil)
	defer hub.Close()

	for i := 0; i < 1000; i++ {
		client := sse.NewClient("bench-user-"+strconv.Itoa(i), "user")
		hub.Register(client)
	}

	event := sse.NewEvent(sse.EventTrafficUpdate, map[string]interface{}{
		"delta": 1024,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hub.Broadcast(event)
	}
}

func postJSON(client *http.Client, url string, payload interface{}, headers map[string]string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// #nosec G107,G704 -- benchmark target URL is intentionally configurable.
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}
