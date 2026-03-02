package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"nodepass-agent/internal/npapi"
	"nodepass-agent/internal/ws"
)

type RelayStartPayload struct {
	Role        string `json:"role,omitempty"`
	EntryRuleID string `json:"entry_rule_id"`
	ExitRuleID  string `json:"exit_rule_id"`
	ListenPort  int    `json:"listen_port"`
	MiddleHost  string `json:"middle_host"`
	MiddlePort  int    `json:"middle_port"`
	TargetHost  string `json:"target_host"`
	TargetPort  int    `json:"target_port"`
	TLSMode     int    `json:"tls_mode"`
	LogLevel    int    `json:"log_level"`
	Password    string `json:"password,omitempty"`
}

type RelayExecutor struct {
	npClient npapiClient
	cache    *InstanceCache
}

func NewRelayExecutor(npClient npapiClient, cache *InstanceCache) *RelayExecutor {
	return &RelayExecutor{npClient: npClient, cache: cache}
}

func (e *RelayExecutor) HandleRelayStart(ctx context.Context, msg ws.HubMessage) error {
	_ = ctx
	var payload RelayStartPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	role := strings.ToLower(strings.TrimSpace(payload.Role))
	if role == "" {
		switch {
		case payload.EntryRuleID != "" && payload.ExitRuleID == "":
			role = "entry"
		case payload.ExitRuleID != "" && payload.EntryRuleID == "":
			role = "exit"
		default:
			return errors.New("unable to infer relay role, provide payload.role")
		}
	}

	switch role {
	case "entry":
		return e.handleEntry(payload)
	case "exit":
		return e.handleExit(payload)
	default:
		return fmt.Errorf("unsupported relay role: %s", role)
	}
}

func (e *RelayExecutor) handleEntry(payload RelayStartPayload) error {
	password := payload.Password
	if password == "" {
		password = GeneratePassword()
	}

	middleListen := net.JoinHostPort("0.0.0.0", strconv.Itoa(payload.MiddlePort))
	middleTarget := net.JoinHostPort("127.0.0.1", strconv.Itoa(payload.MiddlePort))
	externalListen := net.JoinHostPort("0.0.0.0", strconv.Itoa(payload.ListenPort))
	externalTarget := net.JoinHostPort("127.0.0.1", strconv.Itoa(payload.MiddlePort))

	rollback := true
	createdMiddle := ""
	createdExternal := ""
	defer func() {
		if rollback {
			if createdExternal != "" {
				_ = e.npClient.DeleteInstance(createdExternal)
			}
			if createdMiddle != "" {
				_ = e.npClient.DeleteInstance(createdMiddle)
			}
		}
	}()

	middleURL := BuildServerURL(middleListen, middleTarget, password, payload.TLSMode, payload.LogLevel)
	middleIns, err := e.npClient.CreateInstance(npapi.CreateInstanceRequest{URL: middleURL})
	if err != nil {
		return err
	}
	createdMiddle = middleIns.ID
	if err := e.npClient.StartInstance(middleIns.ID); err != nil {
		return err
	}

	externalURL := BuildServerURL(externalListen, externalTarget, password, payload.TLSMode, payload.LogLevel)
	externalIns, err := e.npClient.CreateInstance(npapi.CreateInstanceRequest{URL: externalURL})
	if err != nil {
		return err
	}
	createdExternal = externalIns.ID
	if err := e.npClient.StartInstance(externalIns.ID); err != nil {
		return err
	}

	rollback = false
	_ = e.cache.Set(CacheItem{RuleID: payload.EntryRuleID, InstanceID: externalIns.ID, Status: "running"})
	_ = e.cache.Set(CacheItem{RuleID: payload.EntryRuleID + "_middle", InstanceID: middleIns.ID, Status: "running"})
	return nil
}

func (e *RelayExecutor) handleExit(payload RelayStartPayload) error {
	password := payload.Password
	if password == "" {
		password = GeneratePassword()
	}

	serverAddr := net.JoinHostPort(payload.MiddleHost, strconv.Itoa(payload.MiddlePort))
	targetAddr := net.JoinHostPort(payload.TargetHost, strconv.Itoa(payload.TargetPort))
	url := BuildClientURL(serverAddr, targetAddr, password, payload.TLSMode, payload.LogLevel)

	ins, err := e.npClient.CreateInstance(npapi.CreateInstanceRequest{URL: url})
	if err != nil {
		return err
	}
	if err := e.npClient.StartInstance(ins.ID); err != nil {
		_ = e.npClient.DeleteInstance(ins.ID)
		return err
	}
	_ = e.cache.Set(CacheItem{RuleID: payload.ExitRuleID, InstanceID: ins.ID, Status: "running"})
	return nil
}
