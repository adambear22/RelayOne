package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"nodepass-agent/internal/npapi"
	"nodepass-agent/internal/ws"
)

type npapiClient interface {
	ListInstances() ([]npapi.Instance, error)
	GetInstance(id string) (*npapi.Instance, error)
	CreateInstance(req npapi.CreateInstanceRequest) (*npapi.Instance, error)
	DeleteInstance(id string) error
	StartInstance(id string) error
	StopInstance(id string) error
	UpdateInstance(id string, req npapi.UpdateInstanceRequest) (*npapi.Instance, error)
}

type Executor struct {
	npClient npapiClient
	cache    *InstanceCache
}

type RulePayload struct {
	RuleID     string `json:"rule_id"`
	InstanceID string `json:"instance_id,omitempty"`
	Mode       string `json:"mode,omitempty"`
	ListenAddr string `json:"listen_addr,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	ServerAddr string `json:"server_addr,omitempty"`
	Target     string `json:"target,omitempty"`
	TargetHost string `json:"target_host,omitempty"`
	TargetPort int    `json:"target_port,omitempty"`
	Password   string `json:"password,omitempty"`
	TLSMode    int    `json:"tls_mode,omitempty"`
	LogLevel   int    `json:"log_level,omitempty"`
	URL        string `json:"url,omitempty"`
}

func New(npClient npapiClient, cache *InstanceCache) *Executor {
	return &Executor{npClient: npClient, cache: cache}
}

func (e *Executor) HandleRuleCreate(ctx context.Context, msg ws.HubMessage) error {
	_ = ctx
	payload, err := parseRulePayload(msg.Payload)
	if err != nil {
		return err
	}
	if payload.RuleID == "" {
		return errors.New("rule_id is required")
	}

	if old, ok := e.cache.Get(payload.RuleID); ok && old.InstanceID != "" {
		_ = e.npClient.StopInstance(old.InstanceID)
		_ = e.npClient.DeleteInstance(old.InstanceID)
	}

	url, err := buildRuleURL(payload)
	if err != nil {
		return err
	}

	instance, err := e.npClient.CreateInstance(npapi.CreateInstanceRequest{URL: url})
	if err != nil {
		return err
	}
	if err := e.npClient.StartInstance(instance.ID); err != nil {
		_ = e.npClient.DeleteInstance(instance.ID)
		return err
	}

	return e.cache.Set(CacheItem{
		RuleID:     payload.RuleID,
		InstanceID: instance.ID,
		Status:     "running",
	})
}

func (e *Executor) HandleRuleStart(ctx context.Context, msg ws.HubMessage) error {
	_ = ctx
	payload, err := parseRulePayload(msg.Payload)
	if err != nil {
		return err
	}
	instanceID, err := e.resolveInstanceID(payload)
	if err != nil {
		return err
	}
	if err := e.npClient.StartInstance(instanceID); err != nil {
		return err
	}
	if payload.RuleID != "" {
		item, _ := e.cache.Get(payload.RuleID)
		item.Status = "running"
		item.RuleID = payload.RuleID
		item.InstanceID = instanceID
		_ = e.cache.Set(item)
	}
	return nil
}

func (e *Executor) HandleRuleStop(ctx context.Context, msg ws.HubMessage) error {
	_ = ctx
	payload, err := parseRulePayload(msg.Payload)
	if err != nil {
		return err
	}
	instanceID, err := e.resolveInstanceID(payload)
	if err != nil {
		return err
	}
	if err := e.npClient.StopInstance(instanceID); err != nil {
		return err
	}
	if payload.RuleID != "" {
		item, _ := e.cache.Get(payload.RuleID)
		item.Status = "stopped"
		item.RuleID = payload.RuleID
		item.InstanceID = instanceID
		_ = e.cache.Set(item)
	}
	return nil
}

func (e *Executor) HandleRuleRestart(ctx context.Context, msg ws.HubMessage) error {
	if err := e.HandleRuleStop(ctx, msg); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return e.HandleRuleStart(ctx, msg)
}

func (e *Executor) HandleRuleDelete(ctx context.Context, msg ws.HubMessage) error {
	_ = ctx
	payload, err := parseRulePayload(msg.Payload)
	if err != nil {
		return err
	}
	instanceID, err := e.resolveInstanceID(payload)
	if err != nil {
		return err
	}
	_ = e.npClient.StopInstance(instanceID)
	if err := e.npClient.DeleteInstance(instanceID); err != nil {
		return err
	}
	if payload.RuleID != "" {
		return e.cache.Delete(payload.RuleID)
	}
	return nil
}

func (e *Executor) HandleConfigReload(ctx context.Context, msg ws.HubMessage) error {
	_ = ctx
	_ = msg
	return nil
}

func (e *Executor) RecoverFromCache() error {
	if err := e.cache.Load(); err != nil {
		return err
	}

	instances, err := e.npClient.ListInstances()
	if err != nil {
		return err
	}
	byID := make(map[string]npapi.Instance, len(instances))
	for _, ins := range instances {
		byID[ins.ID] = ins
	}

	for ruleID, cached := range e.cache.Items() {
		ins, ok := byID[cached.InstanceID]
		if !ok {
			_ = e.cache.Delete(ruleID)
			continue
		}
		cached.Status = ins.Status
		_ = e.cache.Set(cached)
	}

	cacheItems := e.cache.Items()
	for _, ins := range instances {
		if ins.RuleID == "" {
			continue
		}
		if _, ok := cacheItems[ins.RuleID]; !ok {
			_ = e.npClient.DeleteInstance(ins.ID)
		}
	}

	return nil
}

func (e *Executor) resolveInstanceID(payload RulePayload) (string, error) {
	if strings.TrimSpace(payload.InstanceID) != "" {
		return strings.TrimSpace(payload.InstanceID), nil
	}
	if strings.TrimSpace(payload.RuleID) == "" {
		return "", errors.New("rule_id or instance_id is required")
	}
	item, ok := e.cache.Get(payload.RuleID)
	if !ok || item.InstanceID == "" {
		return "", fmt.Errorf("instance not found for rule_id=%s", payload.RuleID)
	}
	return item.InstanceID, nil
}

func parseRulePayload(raw json.RawMessage) (RulePayload, error) {
	var payload RulePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, err
	}
	payload.RuleID = strings.TrimSpace(payload.RuleID)
	payload.InstanceID = strings.TrimSpace(payload.InstanceID)
	payload.Mode = strings.TrimSpace(payload.Mode)
	payload.ListenAddr = strings.TrimSpace(payload.ListenAddr)
	payload.ServerAddr = strings.TrimSpace(payload.ServerAddr)
	payload.Target = strings.TrimSpace(payload.Target)
	payload.TargetHost = strings.TrimSpace(payload.TargetHost)
	payload.Password = strings.TrimSpace(payload.Password)
	payload.URL = strings.TrimSpace(payload.URL)
	return payload, nil
}

func buildRuleURL(payload RulePayload) (string, error) {
	if payload.URL != "" {
		return payload.URL, nil
	}
	password := payload.Password
	if password == "" {
		password = GeneratePassword()
	}

	switch strings.ToLower(payload.Mode) {
	case "client":
		serverAddr := payload.ServerAddr
		if serverAddr == "" {
			return "", errors.New("server_addr is required for client mode")
		}
		target := payload.Target
		if target == "" {
			target = net.JoinHostPort(payload.TargetHost, strconv.Itoa(payload.TargetPort))
		}
		if target == "" || target == ":0" {
			return "", errors.New("target is required for client mode")
		}
		return BuildClientURL(serverAddr, target, password, payload.TLSMode, payload.LogLevel), nil
	default:
		listen := payload.ListenAddr
		if listen == "" && payload.ListenPort > 0 {
			listen = net.JoinHostPort("0.0.0.0", strconv.Itoa(payload.ListenPort))
		}
		if listen == "" {
			return "", errors.New("listen_addr or listen_port is required")
		}
		target := payload.Target
		if target == "" && payload.TargetHost != "" && payload.TargetPort > 0 {
			target = net.JoinHostPort(payload.TargetHost, strconv.Itoa(payload.TargetPort))
		}
		if target == "" {
			return "", errors.New("target is required")
		}
		return BuildServerURL(listen, target, password, payload.TLSMode, payload.LogLevel), nil
	}
}
