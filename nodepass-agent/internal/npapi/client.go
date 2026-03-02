package npapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnauthorized = errors.New("npapi: unauthorized")
	ErrNotFound     = errors.New("npapi: instance not found")
	ErrServerError  = errors.New("npapi: server error")
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	mu         sync.RWMutex

	maxAttempts int
	retryDelay  time.Duration
}

func New(masterAddr, apiKey string) *Client {
	return &Client{
		baseURL:     normalizeMasterAddr(masterAddr),
		apiKey:      strings.TrimSpace(apiKey),
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		maxAttempts: 3,
		retryDelay:  500 * time.Millisecond,
	}
}

func (c *Client) UpdateCredentials(masterAddr, apiKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = normalizeMasterAddr(masterAddr)
	c.apiKey = strings.TrimSpace(apiKey)
}

func (c *Client) GetInfo() (*MasterInfo, error) {
	var info MasterInfo
	if err := c.doWithRetry(context.Background(), http.MethodGet, "/api/v1/info", nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *Client) ListInstances() ([]Instance, error) {
	var instances []Instance
	if err := c.doWithRetry(context.Background(), http.MethodGet, "/api/v1/instances", nil, &instances); err != nil {
		return nil, err
	}
	return instances, nil
}

func (c *Client) GetInstance(id string) (*Instance, error) {
	var instance Instance
	if err := c.doWithRetry(context.Background(), http.MethodGet, "/api/v1/instances/"+id, nil, &instance); err != nil {
		return nil, err
	}
	return &instance, nil
}

func (c *Client) CreateInstance(req CreateInstanceRequest) (*Instance, error) {
	var instance Instance
	if err := c.doWithRetry(context.Background(), http.MethodPost, "/api/v1/instances", req, &instance); err != nil {
		return nil, err
	}
	return &instance, nil
}

func (c *Client) DeleteInstance(id string) error {
	return c.doWithRetry(context.Background(), http.MethodDelete, "/api/v1/instances/"+id, nil, nil)
}

func (c *Client) StartInstance(id string) error {
	return c.doWithRetry(context.Background(), http.MethodPost, "/api/v1/instances/"+id+"/start", nil, nil)
}

func (c *Client) StopInstance(id string) error {
	return c.doWithRetry(context.Background(), http.MethodPost, "/api/v1/instances/"+id+"/stop", nil, nil)
}

func (c *Client) UpdateInstance(id string, req UpdateInstanceRequest) (*Instance, error) {
	var instance Instance
	if err := c.doWithRetry(context.Background(), http.MethodPut, "/api/v1/instances/"+id, req, &instance); err != nil {
		return nil, err
	}
	return &instance, nil
}

func (c *Client) doWithRetry(ctx context.Context, method, path string, body any, out any) error {
	var lastErr error
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		err := c.doOnce(ctx, method, path, body, out)
		if err == nil {
			return nil
		}
		lastErr = err

		retry := shouldRetry(err)
		if !retry || attempt == c.maxAttempts {
			break
		}

		timer := time.NewTimer(c.retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func (c *Client) doOnce(ctx context.Context, method, path string, body any, out any) error {
	baseURL, apiKey := c.credentials()
	if baseURL == "" {
		return errors.New("npapi: empty base url")
	}

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(baseURL, "/")+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: status=%d", ErrServerError, resp.StatusCode)
	case resp.StatusCode >= 400:
		return fmt.Errorf("npapi: http %d", resp.StatusCode)
	}

	if out == nil || len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, out); err == nil {
		return nil
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil || len(envelope.Data) == 0 {
		return nil
	}
	return json.Unmarshal(envelope.Data, out)
}

func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNotFound) {
		return false
	}
	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrServerError) {
		return true
	}
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) {
		return true
	}
	if strings.Contains(err.Error(), "connection refused") {
		return true
	}
	return false
}

func normalizeMasterAddr(masterAddr string) string {
	trimmed := strings.TrimSpace(masterAddr)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	return "http://" + trimmed
}

func (c *Client) credentials() (baseURL string, apiKey string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseURL, c.apiKey
}
