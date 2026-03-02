package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type wireMessage struct {
	Type      string          `json:"type"`
	ID        string          `json:"id,omitempty"`
	Timestamp time.Time       `json:"timestamp,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type instance struct {
	ID                string `json:"id"`
	RuleID            string `json:"rule_id"`
	URL               string `json:"url"`
	Status            string `json:"status"`
	ActiveConnections int    `json:"active_connections"`
	BytesIn           int64  `json:"bytes_in"`
	BytesOut          int64  `json:"bytes_out"`
}

type npapiServer struct {
	addr      string
	server    *http.Server
	mu        sync.Mutex
	instances map[string]*instance
	nextID    int
}

func newNPAPIServer(listener net.Listener) *npapiServer {
	s := &npapiServer{
		addr:      listener.Addr().String(),
		instances: make(map[string]*instance),
		nextID:    1,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/info", s.handleInfo)
	mux.HandleFunc("/api/v1/instances", s.handleInstances)
	mux.HandleFunc("/api/v1/instances/", s.handleInstanceByID)

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("npapi server error: %v", err)
		}
	}()
	return s
}

func (s *npapiServer) shutdown(ctx context.Context) {
	_ = s.server.Shutdown(ctx)
}

func (s *npapiServer) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"version": "smoke"})
}

func (s *npapiServer) handleInstances(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		out := make([]instance, 0, len(s.instances))
		for _, ins := range s.instances {
			if ins.Status == "running" {
				ins.BytesIn += 128
				ins.BytesOut += 96
				ins.ActiveConnections = 2
			}
			out = append(out, *ins)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	case http.MethodPost:
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id := fmt.Sprintf("ins-%d", s.nextID)
		s.nextID++
		ins := &instance{
			ID:                id,
			RuleID:            "rule-1",
			URL:               req.URL,
			Status:            "created",
			ActiveConnections: 0,
		}
		s.instances[id] = ins
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ins)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *npapiServer) handleInstanceByID(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/instances/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	id := strings.TrimSpace(parts[0])
	action := ""
	if len(parts) > 1 {
		action = strings.TrimSpace(parts[1])
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	ins, ok := s.instances[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	switch {
	case r.Method == http.MethodDelete && action == "":
		delete(s.instances, id)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && action == "start":
		ins.Status = "running"
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && action == "stop":
		ins.Status = "stopped"
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && action == "":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ins)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type hubObserver struct {
	mu          sync.Mutex
	agentHello  bool
	configACK   bool
	pong        bool
	status      bool
	traffic     bool
	configMsgID string
	pingMsgID   string
	doneCh      chan struct{}
	once        sync.Once
}

func newHubObserver() *hubObserver {
	return &hubObserver{doneCh: make(chan struct{})}
}

func (o *hubObserver) mark(check func()) {
	o.mu.Lock()
	defer o.mu.Unlock()
	check()
	if o.agentHello && o.configACK && o.pong && o.status && o.traffic {
		o.once.Do(func() { close(o.doneCh) })
	}
}

func (o *hubObserver) snapshot() map[string]bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return map[string]bool{
		"agent_hello": o.agentHello,
		"config_ack":  o.configACK,
		"pong":        o.pong,
		"status":      o.status,
		"traffic":     o.traffic,
	}
}

func main() {
	repoRoot, err := os.Getwd()
	if err != nil {
		log.Fatalf("getwd: %v", err)
	}
	agentBin := filepath.Join(repoRoot, "nodepass-agent", "bin", "nodepass-agent")
	if _, err := os.Stat(agentBin); err != nil {
		log.Fatalf("agent binary not found: %v", err)
	}

	timeout := 35 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	npLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen npapi: %v", err)
	}
	npSrv := newNPAPIServer(npLn)
	defer npSrv.shutdown(context.Background())

	observer := newHubObserver()

	hubLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen hub: %v", err)
	}
	hubAddr := hubLn.Addr().String()
	npAddr := npLn.Addr().String()

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	hubMux := http.NewServeMux()
	hubMux.HandleFunc("/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		conn, upErr := upgrader.Upgrade(w, r, nil)
		if upErr != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		configMsgID := fmt.Sprintf("cfg-%d", time.Now().UnixNano())
		pingMsgID := fmt.Sprintf("ping-%d", time.Now().UnixNano())

		observer.mu.Lock()
		observer.configMsgID = configMsgID
		observer.pingMsgID = pingMsgID
		observer.mu.Unlock()

		for {
			_, raw, readErr := conn.ReadMessage()
			if readErr != nil {
				return
			}
			var msg wireMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				continue
			}

			switch strings.ToLower(strings.TrimSpace(msg.Type)) {
			case "agenthello":
				observer.mark(func() { observer.agentHello = true })
				cfgPayload := map[string]any{
					"rule_id":      "rule-1",
					"action":       "start",
					"nodepass_url": "nodepass://server:pass@0.0.0.0:10080/127.0.0.1:8080?tls=0&log=1",
					"target":       "127.0.0.1:8080",
				}
				cfgRaw, _ := json.Marshal(cfgPayload)
				_ = conn.WriteJSON(wireMessage{Type: "ConfigPush", ID: configMsgID, Timestamp: time.Now().UTC(), Payload: cfgRaw})
				pingRaw, _ := json.Marshal(map[string]int64{"timestamp": time.Now().Unix()})
				_ = conn.WriteJSON(wireMessage{Type: "Ping", ID: pingMsgID, Timestamp: time.Now().UTC(), Payload: pingRaw})
			case "ack":
				if msg.ID == configMsgID {
					var p struct {
						Success bool `json:"success"`
					}
					_ = json.Unmarshal(msg.Payload, &p)
					if p.Success {
						observer.mark(func() { observer.configACK = true })
					}
				}
			case "pong":
				if msg.ID == pingMsgID {
					observer.mark(func() { observer.pong = true })
				}
			case "statusreport":
				observer.mark(func() { observer.status = true })
			case "trafficreport":
				observer.mark(func() { observer.traffic = true })
				ackPayload, _ := json.Marshal(map[string]any{"success": true})
				_ = conn.WriteJSON(wireMessage{Type: "Ack", ID: msg.ID, Timestamp: time.Now().UTC(), Payload: ackPayload})
			}
		}
	})

	hubSrv := &http.Server{
		Handler:           hubMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := hubSrv.Serve(hubLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("hub server error: %v", err)
		}
	}()
	defer func() {
		_ = hubSrv.Shutdown(context.Background())
	}()

	agentID := randomAgentID()
	workDir, err := os.MkdirTemp("", "nodepass-agent-smoke-")
	if err != nil {
		log.Fatalf("temp dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(workDir)
	}()

	if err := prepareNodepassScript(workDir, npAddr, "smoke-key"); err != nil {
		log.Fatalf("prepare nodepass script: %v", err)
	}

	agentCtx, agentCancel := context.WithCancel(ctx)
	defer agentCancel()
	configPath := filepath.Join(workDir, "agent.conf")
	cmd := exec.CommandContext(agentCtx, agentBin, "--config", configPath, "--workdir", workDir) //nolint:gosec
	cmd.Env = append(os.Environ(),
		"HUB_URL=ws://"+hubAddr+"/ws/agent",
		"AGENT_ID="+agentID,
		"INTERNAL_TOKEN=smoke-token",
		"WORK_DIR="+workDir,
		"METRICS_INTERVAL=1",
		"TRAFFIC_INTERVAL=1",
	)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		log.Fatalf("start agent: %v", err)
	}

	go streamPrefix("agent", stdout)
	go streamPrefix("agent", stderr)

	select {
	case <-observer.doneCh:
		fmt.Println("SMOKE_OK", toJSON(observer.snapshot()))
		agentCancel()
		_ = cmd.Wait()
		return
	case <-ctx.Done():
		agentCancel()
		_ = cmd.Wait()
		log.Fatalf("smoke timeout: %s state=%s", timeout.String(), toJSON(observer.snapshot()))
	}
}

func prepareNodepassScript(workDir, npapiAddr, apiKey string) error {
	binDir := filepath.Join(workDir, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "nodepass")

	script := strings.Join([]string{
		"#!/bin/sh",
		"echo \"MASTER_ADDR=" + npapiAddr + "\"",
		"echo \"API_KEY=" + apiKey + "\"",
		"while true; do sleep 1; done",
		"",
	}, "\n")
	if err := os.WriteFile(binPath, []byte(script), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(binPath, 0o700); err != nil { //nolint:gosec
		return err
	}

	version := "0.0.0-dev"
	return os.WriteFile(binPath+".version", []byte(version+"\n"), 0o600)
}

func streamPrefix(_ string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
	}
}

func toJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func randomAgentID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("agent-%d", time.Now().UnixNano())
	}

	hexValue := hex.EncodeToString(buf)
	return fmt.Sprintf(
		"%s-%s-%s-%s-%s",
		hexValue[0:8],
		hexValue[8:12],
		hexValue[12:16],
		hexValue[16:20],
		hexValue[20:32],
	)
}
