package npapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientRetriesOnServerError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/instances" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode([]Instance{{ID: "ins-1"}})
	}))
	defer srv.Close()

	cli := New(srv.URL, "token")
	cli.retryDelay = 10 * time.Millisecond

	instances, err := cli.ListInstances()
	if err != nil {
		t.Fatalf("list instances: %v", err)
	}
	if len(instances) != 1 || instances[0].ID != "ins-1" {
		t.Fatalf("unexpected instances: %+v", instances)
	}
	if calls.Load() < 2 {
		t.Fatalf("expected retry, calls=%d", calls.Load())
	}
}

func TestClientDoesNotRetryNotFound(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cli := New(srv.URL, "token")
	cli.retryDelay = 10 * time.Millisecond

	_, err := cli.GetInstance("missing")
	if err == nil {
		t.Fatalf("expected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected no retry for 404, calls=%d", calls.Load())
	}
}

func TestClientRetriesAfterCredentialUpdate(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(MasterInfo{Version: "0.6.2"})
	}))
	defer srv.Close()

	cli := New(srv.URL, "old-token")
	cli.retryDelay = 50 * time.Millisecond
	cli.maxAttempts = 4

	go func() {
		time.Sleep(70 * time.Millisecond)
		cli.UpdateCredentials(srv.URL, "new-token")
	}()

	info, err := cli.GetInfo()
	if err != nil {
		t.Fatalf("get info: %v", err)
	}
	if info.Version != "0.6.2" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if calls.Load() < 2 {
		t.Fatalf("expected retry after credential update")
	}
}
