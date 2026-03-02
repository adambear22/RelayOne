package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/metrics"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/sse"
)

const (
	ruleStatusStopped    = "stopped"
	ruleStatusRunning    = "running"
	ruleStatusPaused     = "paused"
	ruleSyncPending      = "pending_sync"
	ruleSyncSynced       = "synced"
	ruleSyncFailed       = "sync_failed"
	ruleActionStart      = "start"
	ruleActionStop       = "stop"
	ruleActionRestart    = "restart"
	ruleActionSync       = "sync"
	ruleDefaultMode      = "single"
	ruleListDefaultPage  = 1
	ruleListDefaultSize  = 20
	ruleListMaxPageSize  = 200
	ruleSyncWaitTimeout  = 10 * time.Second
	ruleResourceTypeName = "rule"
)

var (
	ErrRuleNotFound      = errors.New("rule not found")
	ErrInvalidRuleID     = errors.New("invalid rule id")
	ErrInvalidRuleInput  = errors.New("invalid rule input")
	ErrRuleLimitExceeded = errors.New("rule limit exceeded")
	ErrRuleNotEditable   = errors.New("rule is not editable")
	ErrRuleSyncTimeout   = errors.New("rule sync timeout")
	ErrNodeOffline       = errors.New("node offline")
)

type RuleCommandHub interface {
	SendConfigPushAndWaitAck(
		ctx context.Context,
		agentID string,
		ruleID string,
		action string,
		nodepassURL string,
		target string,
		timeout time.Duration,
	) (bool, error)
}

type RuleLBEgressService interface {
	SelectEgress(ctx context.Context, groupID, clientIP string) (*model.NodeAgent, error)
}

type RuleHopChainService interface {
	DispatchHopChain(ctx context.Context, chainID, ruleID string) error
}

type CreateRuleRequest struct {
	Name          string  `json:"name"`
	Mode          string  `json:"mode"`
	IngressNodeID string  `json:"ingress_node_id"`
	TargetHost    string  `json:"target_host"`
	TargetPort    int     `json:"target_port"`
	EgressNodeID  *string `json:"egress_node_id"`
	LBGroupID     *string `json:"lb_group_id"`
	HopChainID    *string `json:"hop_chain_id"`
	NpTLS         *int    `json:"np_tls"`
	NpMode        *string `json:"np_mode"`
	NpMin         *int    `json:"np_min"`
	NpMax         *int    `json:"np_max"`
	NpRate        *int    `json:"np_rate"`
	NpNoTCP       *bool   `json:"np_notcp"`
	NpNoUDP       *bool   `json:"np_noudp"`
	NpLog         *string `json:"np_log"`
}

type UpdateRuleRequest struct {
	Name          *string `json:"name"`
	Mode          *string `json:"mode"`
	IngressNodeID *string `json:"ingress_node_id"`
	TargetHost    *string `json:"target_host"`
	TargetPort    *int    `json:"target_port"`
	EgressNodeID  *string `json:"egress_node_id"`
	LBGroupID     *string `json:"lb_group_id"`
	HopChainID    *string `json:"hop_chain_id"`
	NpTLS         *int    `json:"np_tls"`
	NpMode        *string `json:"np_mode"`
	NpMin         *int    `json:"np_min"`
	NpMax         *int    `json:"np_max"`
	NpRate        *int    `json:"np_rate"`
	NpNoTCP       *bool   `json:"np_notcp"`
	NpNoUDP       *bool   `json:"np_noudp"`
	NpLog         *string `json:"np_log"`
}

type RuleListFilter struct {
	OwnerID    *string
	NodeID     *string
	Mode       *string
	Status     *string
	SyncStatus *string
}

type InstanceInfo struct {
	RuleID        string                 `json:"rule_id"`
	Status        string                 `json:"status"`
	SyncStatus    string                 `json:"sync_status"`
	Mode          string                 `json:"mode"`
	IngressNodeID string                 `json:"ingress_node_id"`
	IngressPort   int                    `json:"ingress_port"`
	Target        string                 `json:"target"`
	NodePassURL   string                 `json:"nodepass_url"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type RuleService struct {
	ruleRepo    repository.RuleRepository
	userRepo    repository.UserRepository
	nodeRepo    repository.NodeRepository
	auditRepo   repository.AuditRepository
	pool        *pgxpool.Pool
	hub         RuleCommandHub
	sseHub      *sse.SSEHub
	lbSvc       RuleLBEgressService
	hopChainSvc RuleHopChainService
	logger      *zap.Logger
}

func NewRuleService(
	ruleRepo repository.RuleRepository,
	userRepo repository.UserRepository,
	nodeRepo repository.NodeRepository,
	auditRepo repository.AuditRepository,
	pool *pgxpool.Pool,
	hub RuleCommandHub,
	sseHub *sse.SSEHub,
	lbSvc RuleLBEgressService,
	hopChainSvc RuleHopChainService,
	nodeService *NodeService,
	logger *zap.Logger,
) *RuleService {
	if logger == nil {
		logger = zap.NewNop()
	}
	if nodeService != nil {
		ruleRepo = nodeService.WrapRuleRepository(ruleRepo)
	}

	return &RuleService{
		ruleRepo:    ruleRepo,
		userRepo:    userRepo,
		nodeRepo:    nodeRepo,
		auditRepo:   auditRepo,
		pool:        pool,
		hub:         hub,
		sseHub:      sseHub,
		lbSvc:       lbSvc,
		hopChainSvc: hopChainSvc,
		logger:      logger,
	}
}

func (s *RuleService) Create(ctx context.Context, ownerID string, req CreateRuleRequest) (*model.ForwardingRule, error) {
	ownerUUID, err := uuid.Parse(strings.TrimSpace(ownerID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	ingressNodeID, err := uuid.Parse(strings.TrimSpace(req.IngressNodeID))
	if err != nil {
		return nil, ErrInvalidRuleInput
	}

	name := strings.TrimSpace(req.Name)
	mode := strings.TrimSpace(req.Mode)
	targetHost := strings.TrimSpace(req.TargetHost)
	if name == "" || targetHost == "" || req.TargetPort <= 0 {
		return nil, ErrInvalidRuleInput
	}
	if mode == "" {
		mode = ruleDefaultMode
	}
	if !isSupportedRuleMode(mode) {
		return nil, ErrInvalidRuleInput
	}

	if _, err := s.nodeRepo.FindByID(ctx, ingressNodeID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}

	maxRules, err := s.userMaxRules(ctx, ownerUUID)
	if err != nil {
		return nil, err
	}
	activeCount, err := s.countActiveRules(ctx, ownerUUID)
	if err != nil {
		return nil, err
	}
	if maxRules > 0 && activeCount >= int64(maxRules) {
		return nil, ErrRuleLimitExceeded
	}

	override := nodePassParamsFromCreateRequest(req)
	if err := Validate(override); err != nil {
		return nil, err
	}

	rule := &model.ForwardingRule{
		ID:            uuid.New(),
		Name:          name,
		OwnerID:       ownerUUID,
		Mode:          mode,
		IngressNodeID: ingressNodeID,
		TargetHost:    targetHost,
		TargetPort:    req.TargetPort,
		Status:        ruleStatusStopped,
		SyncStatus:    ruleSyncPending,
		NpParams:      toModelNpParams(override),
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}

	if req.EgressNodeID != nil && strings.TrimSpace(*req.EgressNodeID) != "" {
		egressID, err := uuid.Parse(strings.TrimSpace(*req.EgressNodeID))
		if err != nil {
			return nil, ErrInvalidRuleInput
		}
		rule.EgressNodeID = &egressID
	}
	if req.LBGroupID != nil && strings.TrimSpace(*req.LBGroupID) != "" {
		lbID, err := uuid.Parse(strings.TrimSpace(*req.LBGroupID))
		if err != nil {
			return nil, ErrInvalidRuleInput
		}
		rule.LBGroupID = &lbID
	}
	if req.HopChainID != nil && strings.TrimSpace(*req.HopChainID) != "" {
		hopID, err := uuid.Parse(strings.TrimSpace(*req.HopChainID))
		if err != nil {
			return nil, ErrInvalidRuleInput
		}
		rule.HopChainID = &hopID
	}

	if err := s.ruleRepo.Create(ctx, rule); err != nil {
		return nil, err
	}

	s.writeAudit(ctx, ownerID, "rule.create", rule.ID.String(), nil, map[string]interface{}{
		"id":        rule.ID.String(),
		"name":      rule.Name,
		"mode":      rule.Mode,
		"status":    rule.Status,
		"node_id":   rule.IngressNodeID.String(),
		"node_port": rule.IngressPort,
	})

	return rule, nil
}

func (s *RuleService) List(ctx context.Context, page, pageSize int, filter RuleListFilter) ([]*model.ForwardingRule, int64, error) {
	page, pageSize = normalizeRuleListPage(page, pageSize)

	repoFilter := repository.RuleListFilter{
		Pagination: repository.Pagination{
			Limit:  clampIntToInt32(pageSize),
			Offset: clampIntToInt32((page - 1) * pageSize),
		},
	}

	if filter.OwnerID != nil {
		ownerID, err := uuid.Parse(strings.TrimSpace(*filter.OwnerID))
		if err != nil {
			return nil, 0, ErrInvalidUserID
		}
		repoFilter.OwnerID = &ownerID
	}
	if filter.NodeID != nil {
		nodeID, err := uuid.Parse(strings.TrimSpace(*filter.NodeID))
		if err != nil {
			return nil, 0, ErrInvalidNodeID
		}
		repoFilter.NodeID = &nodeID
	}
	if filter.Mode != nil {
		mode := strings.TrimSpace(*filter.Mode)
		if mode != "" {
			repoFilter.Mode = &mode
		}
	}
	if filter.Status != nil {
		status := strings.TrimSpace(*filter.Status)
		if status != "" {
			repoFilter.Status = &status
		}
	}
	if filter.SyncStatus != nil {
		syncStatus := strings.TrimSpace(*filter.SyncStatus)
		if syncStatus != "" {
			repoFilter.SyncStatus = &syncStatus
		}
	}

	items, err := s.ruleRepo.List(ctx, repoFilter)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.countRules(ctx, repoFilter)
	if err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *RuleService) GetByID(ctx context.Context, id string) (*model.ForwardingRule, error) {
	ruleID, err := uuid.Parse(strings.TrimSpace(id))
	if err != nil {
		return nil, ErrInvalidRuleID
	}

	rule, err := s.ruleRepo.FindByID(ctx, ruleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrRuleNotFound
		}
		return nil, err
	}
	return rule, nil
}

func (s *RuleService) Update(ctx context.Context, ruleID string, req UpdateRuleRequest, operatorID string) (*model.ForwardingRule, error) {
	rule, err := s.GetByID(ctx, ruleID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(rule.Status, ruleStatusStopped) {
		return nil, ErrRuleNotEditable
	}

	oldValue := map[string]interface{}{
		"name":        rule.Name,
		"mode":        rule.Mode,
		"target_host": rule.TargetHost,
		"target_port": rule.TargetPort,
	}

	if req.Name != nil {
		rule.Name = strings.TrimSpace(*req.Name)
	}
	if req.Mode != nil {
		rule.Mode = strings.TrimSpace(*req.Mode)
	}
	if req.TargetHost != nil {
		rule.TargetHost = strings.TrimSpace(*req.TargetHost)
	}
	if req.TargetPort != nil {
		rule.TargetPort = *req.TargetPort
	}
	if req.IngressNodeID != nil {
		nodeID, err := parseOptionalUUID(*req.IngressNodeID)
		if err != nil || nodeID == nil {
			return nil, ErrInvalidRuleInput
		}
		rule.IngressNodeID = *nodeID
	}

	egressNodeID, err := parseOptionalUUIDPtr(req.EgressNodeID)
	if err != nil {
		return nil, ErrInvalidRuleInput
	}
	if req.EgressNodeID != nil {
		rule.EgressNodeID = egressNodeID
	}

	lbGroupID, err := parseOptionalUUIDPtr(req.LBGroupID)
	if err != nil {
		return nil, ErrInvalidRuleInput
	}
	if req.LBGroupID != nil {
		rule.LBGroupID = lbGroupID
	}

	hopChainID, err := parseOptionalUUIDPtr(req.HopChainID)
	if err != nil {
		return nil, ErrInvalidRuleInput
	}
	if req.HopChainID != nil {
		rule.HopChainID = hopChainID
	}

	if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.TargetHost) == "" || rule.TargetPort <= 0 {
		return nil, ErrInvalidRuleInput
	}
	if strings.TrimSpace(rule.Mode) == "" {
		rule.Mode = ruleDefaultMode
	}
	if !isSupportedRuleMode(rule.Mode) {
		return nil, ErrInvalidRuleInput
	}

	mergedParams := modelNpParamsToNodePass(rule.NpParams)
	applyNodePassOverride(&mergedParams, req)
	if err := Validate(mergedParams); err != nil {
		return nil, err
	}
	rule.NpParams = toModelNpParams(mergedParams)

	if err := s.ruleRepo.Update(ctx, rule); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrRuleNotFound
		}
		return nil, err
	}

	newValue := map[string]interface{}{
		"name":        rule.Name,
		"mode":        rule.Mode,
		"target_host": rule.TargetHost,
		"target_port": rule.TargetPort,
	}
	s.writeAudit(ctx, operatorID, "rule.update", rule.ID.String(), oldValue, newValue)

	return rule, nil
}

func (s *RuleService) Delete(ctx context.Context, ruleID, operatorID string) error {
	rule, err := s.GetByID(ctx, ruleID)
	if err != nil {
		return err
	}

	if err := s.ruleRepo.Delete(ctx, rule.ID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrRuleNotFound
		}
		return err
	}

	s.writeAudit(ctx, operatorID, "rule.delete", rule.ID.String(), map[string]interface{}{
		"id":      rule.ID.String(),
		"name":    rule.Name,
		"status":  rule.Status,
		"node_id": rule.IngressNodeID.String(),
	}, nil)

	return nil
}

func (s *RuleService) BatchDelete(ctx context.Context, operatorID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	uuids := make([]uuid.UUID, 0, len(ids))
	for _, rawID := range ids {
		id, err := uuid.Parse(strings.TrimSpace(rawID))
		if err != nil {
			return ErrInvalidRuleID
		}
		uuids = append(uuids, id)
	}

	if err := s.ruleRepo.BatchDelete(ctx, uuids); err != nil {
		return err
	}

	s.writeAudit(ctx, operatorID, "rule.batch_delete", "", map[string]interface{}{"ids": ids}, nil)
	return nil
}

func (s *RuleService) Start(ctx context.Context, ruleID, operatorID string) error {
	return s.dispatchRuleAction(ctx, ruleID, operatorID, ruleActionStart, "")
}

func (s *RuleService) Stop(ctx context.Context, ruleID, operatorID string) error {
	return s.dispatchRuleAction(ctx, ruleID, operatorID, ruleActionStop, "")
}

func (s *RuleService) Restart(ctx context.Context, ruleID, operatorID string) error {
	return s.dispatchRuleAction(ctx, ruleID, operatorID, ruleActionRestart, "")
}

func (s *RuleService) SyncRule(ctx context.Context, ruleID string) error {
	return s.dispatchRuleAction(ctx, ruleID, "", ruleActionSync, "")
}

func (s *RuleService) PauseAllUserRules(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return ErrInvalidUserID
	}

	running := ruleStatusRunning
	pageSize := 200
	offset := 0

	var firstErr error
	for {
		rules, err := s.ruleRepo.List(ctx, repository.RuleListFilter{
			OwnerID: &uid,
			Status:  &running,
			Pagination: repository.Pagination{
				Limit:  int32(pageSize),
				Offset: int32(offset),
			},
		})
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			break
		}

		for _, rule := range rules {
			if rule == nil {
				continue
			}
			err := s.dispatchRuleAction(ctx, rule.ID.String(), "", ruleActionStop, ruleStatusPaused)
			if err == nil {
				continue
			}

			if firstErr == nil {
				firstErr = err
			}
			s.logger.Warn("pause user rule via hub failed, fallback to db status update",
				zap.String("user_id", uid.String()),
				zap.String("rule_id", rule.ID.String()),
				zap.Error(err),
			)

			_ = s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, ruleSyncFailed)
			_ = s.ruleRepo.UpdateStatus(ctx, rule.ID, ruleStatusPaused)
		}

		if len(rules) < pageSize {
			break
		}
		offset += len(rules)
	}

	return firstErr
}

func (s *RuleService) ResumeAllUserRules(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return ErrInvalidUserID
	}

	paused := ruleStatusPaused
	pageSize := 200
	offset := 0

	var firstErr error
	for {
		rules, err := s.ruleRepo.List(ctx, repository.RuleListFilter{
			OwnerID: &uid,
			Status:  &paused,
			Pagination: repository.Pagination{
				Limit:  int32(pageSize),
				Offset: int32(offset),
			},
		})
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			break
		}

		for _, rule := range rules {
			if rule == nil {
				continue
			}
			if err := s.dispatchRuleAction(ctx, rule.ID.String(), "", ruleActionStart, ""); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				s.logger.Warn("resume user rule failed",
					zap.String("user_id", uid.String()),
					zap.String("rule_id", rule.ID.String()),
					zap.Error(err),
				)
			}
		}

		if len(rules) < pageSize {
			break
		}
		offset += len(rules)
	}

	return firstErr
}

func (s *RuleService) SyncUserRunningRules(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return ErrInvalidUserID
	}

	running := ruleStatusRunning
	pageSize := 200
	offset := 0

	var firstErr error
	for {
		rules, err := s.ruleRepo.List(ctx, repository.RuleListFilter{
			OwnerID: &uid,
			Status:  &running,
			Pagination: repository.Pagination{
				Limit:  int32(pageSize),
				Offset: int32(offset),
			},
		})
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			break
		}

		for _, rule := range rules {
			if rule == nil {
				continue
			}
			if err := s.dispatchRuleAction(ctx, rule.ID.String(), "", ruleActionSync, ""); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				s.logger.Warn("sync user running rule failed",
					zap.String("user_id", uid.String()),
					zap.String("rule_id", rule.ID.String()),
					zap.Error(err),
				)
			}
		}

		if len(rules) < pageSize {
			break
		}
		offset += len(rules)
	}

	return firstErr
}

func (s *RuleService) GetInstanceInfo(ctx context.Context, ruleID string) (*InstanceInfo, error) {
	rule, err := s.GetByID(ctx, ruleID)
	if err != nil {
		return nil, err
	}

	node, err := s.nodeRepo.FindByID(ctx, rule.IngressNodeID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}

	systemDefaults, _ := s.loadSystemDefaults(ctx)
	nodeDefaults := NodePassParams{}
	if node != nil {
		nodeDefaults = parseNodeDefaultsFromNode(node)
	}
	params := Compile(systemDefaults, nodeDefaults, modelNpParamsToNodePass(rule.NpParams))
	_ = Validate(params)

	target := net.JoinHostPort(rule.TargetHost, strconv.Itoa(rule.TargetPort))
	info := &InstanceInfo{
		RuleID:        rule.ID.String(),
		Status:        rule.Status,
		SyncStatus:    rule.SyncStatus,
		Mode:          rule.Mode,
		IngressNodeID: rule.IngressNodeID.String(),
		IngressPort:   rule.IngressPort,
		Target:        target,
		NodePassURL:   BuildURL(rule.Mode, rule.TargetHost, rule.TargetPort, "", "", params),
	}

	if len(rule.InstanceInfo) > 0 {
		info.Metadata = cloneMap(rule.InstanceInfo)
	}

	return info, nil
}

func (s *RuleService) dispatchRuleAction(ctx context.Context, ruleID, operatorID, action, forcedStatus string) (err error) {
	syncStartedAt := time.Now()
	defer func() {
		metrics.ObserveRuleSyncDuration(time.Since(syncStartedAt))
		if err != nil {
			metrics.IncRuleSyncError()
		}
	}()

	rule, err := s.GetByID(ctx, ruleID)
	if err != nil {
		return err
	}
	if s.hub == nil {
		return errors.New("rule command hub is nil")
	}

	mode := strings.ToLower(strings.TrimSpace(rule.Mode))
	startLikeAction := action == ruleActionStart || action == ruleActionRestart || action == ruleActionSync
	if startLikeAction && mode == "hop_chain" {
		if rule.HopChainID == nil {
			return ErrInvalidRuleInput
		}
		if s.hopChainSvc == nil {
			return ErrInvalidRuleInput
		}

		if err := s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, ruleSyncPending); err != nil {
			return err
		}
		if err := s.hopChainSvc.DispatchHopChain(ctx, rule.HopChainID.String(), rule.ID.String()); err != nil {
			_ = s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, ruleSyncFailed)
			s.emitRuleStatus(rule, action, rule.Status, ruleSyncFailed, err)
			return err
		}

		nextStatus := strings.TrimSpace(forcedStatus)
		if nextStatus == "" {
			nextStatus = nextRuleStatus(action, rule.Status)
		}
		if nextStatus != "" && nextStatus != rule.Status {
			if err := s.ruleRepo.UpdateStatus(ctx, rule.ID, nextStatus); err != nil {
				return err
			}
			rule.Status = nextStatus
		}
		rule.SyncStatus = ruleSyncSynced

		_ = s.updateRuleInstanceInfo(ctx, rule.ID, map[string]interface{}{
			"action":       action,
			"synced":       true,
			"mode":         "hop_chain",
			"hop_chain_id": rule.HopChainID.String(),
			"acked_at":     time.Now().UTC().Format(time.RFC3339Nano),
		})

		s.emitRuleStatus(rule, action, rule.Status, rule.SyncStatus, nil)
		s.writeAudit(ctx, operatorID, "rule."+action, rule.ID.String(), nil, map[string]interface{}{
			"rule_id":      rule.ID.String(),
			"action":       action,
			"status":       rule.Status,
			"sync_status":  rule.SyncStatus,
			"ingress_node": rule.IngressNodeID.String(),
			"mode":         rule.Mode,
		})

		return nil
	}

	node, err := s.nodeRepo.FindByID(ctx, rule.IngressNodeID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNodeNotFound
		}
		return err
	}
	if node == nil || !strings.EqualFold(strings.TrimSpace(node.Status), "online") {
		return ErrNodeOffline
	}

	systemDefaults, err := s.loadSystemDefaults(ctx)
	if err != nil {
		return err
	}
	nodeDefaults := parseNodeDefaultsFromNode(node)
	override := modelNpParamsToNodePass(rule.NpParams)
	params := Compile(systemDefaults, nodeDefaults, override)
	if err := s.applyUserBandwidthLimit(ctx, rule.OwnerID, &params); err != nil {
		return err
	}
	if err := Validate(params); err != nil {
		return err
	}

	dispatchHost := rule.TargetHost
	dispatchPort := rule.TargetPort
	instanceType := rule.Mode
	selectedEgressNodeID := ""

	if startLikeAction && mode == "lb" {
		if rule.LBGroupID == nil {
			return ErrInvalidRuleInput
		}
		if s.lbSvc == nil {
			return ErrInvalidRuleInput
		}

		egressNode, err := s.lbSvc.SelectEgress(ctx, rule.LBGroupID.String(), "")
		if err != nil {
			return err
		}

		dispatchHost = egressNode.Host
		dispatchPort = egressNode.APIPort
		instanceType = "single"
		selectedEgressNodeID = egressNode.ID.String()
	}

	nodePassURL := BuildURL(instanceType, dispatchHost, dispatchPort, "", "", params)
	target := net.JoinHostPort(dispatchHost, strconv.Itoa(dispatchPort))
	now := time.Now().UTC()

	if err := s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, ruleSyncPending); err != nil {
		return err
	}

	instancePatch := map[string]interface{}{
		"action":       action,
		"nodepass_url": nodePassURL,
		"target":       target,
		"requested_at": now.Format(time.RFC3339Nano),
		"mode":         rule.Mode,
	}
	if selectedEgressNodeID != "" {
		instancePatch["selected_egress_node_id"] = selectedEgressNodeID
	}
	_ = s.updateRuleInstanceInfo(ctx, rule.ID, instancePatch)

	acked, err := s.hub.SendConfigPushAndWaitAck(
		ctx,
		node.ID.String(),
		rule.ID.String(),
		action,
		nodePassURL,
		target,
		ruleSyncWaitTimeout,
	)
	if err != nil {
		_ = s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, ruleSyncFailed)
		s.emitRuleStatus(rule, action, rule.Status, ruleSyncFailed, err)
		return err
	}
	if !acked {
		_ = s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, ruleSyncFailed)
		s.emitRuleStatus(rule, action, rule.Status, ruleSyncFailed, ErrRuleSyncTimeout)
		return ErrRuleSyncTimeout
	}

	nextStatus := strings.TrimSpace(forcedStatus)
	if nextStatus == "" {
		nextStatus = nextRuleStatus(action, rule.Status)
	}
	if err := s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, ruleSyncSynced); err != nil {
		return err
	}
	if nextStatus != "" && nextStatus != rule.Status {
		if err := s.ruleRepo.UpdateStatus(ctx, rule.ID, nextStatus); err != nil {
			return err
		}
		rule.Status = nextStatus
	}
	rule.SyncStatus = ruleSyncSynced

	_ = s.updateRuleInstanceInfo(ctx, rule.ID, map[string]interface{}{
		"action":    action,
		"acked_at":  time.Now().UTC().Format(time.RFC3339Nano),
		"synced":    true,
		"node_id":   node.ID.String(),
		"node_port": rule.IngressPort,
	})

	s.emitRuleStatus(rule, action, rule.Status, rule.SyncStatus, nil)
	s.writeAudit(ctx, operatorID, "rule."+action, rule.ID.String(), nil, map[string]interface{}{
		"rule_id":      rule.ID.String(),
		"action":       action,
		"status":       rule.Status,
		"sync_status":  rule.SyncStatus,
		"ingress_node": rule.IngressNodeID.String(),
		"mode":         rule.Mode,
	})

	return nil
}

func (s *RuleService) countActiveRules(ctx context.Context, ownerID uuid.UUID) (int64, error) {
	if s.pool == nil {
		return 0, errors.New("database pool is nil")
	}

	var count int64
	err := s.pool.QueryRow(
		ctx,
		`SELECT COUNT(*)
		 FROM forwarding_rules
		 WHERE owner_id = $1
		   AND status IN ('running', 'paused')`,
		ownerID,
	).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *RuleService) countRules(ctx context.Context, filter repository.RuleListFilter) (int64, error) {
	if s.pool == nil {
		return 0, errors.New("database pool is nil")
	}

	args := make([]any, 0, 6)
	conditions := make([]string, 0, 5)

	if filter.OwnerID != nil {
		args = append(args, *filter.OwnerID)
		conditions = append(conditions, "owner_id = $"+strconv.Itoa(len(args)))
	}
	if filter.NodeID != nil {
		args = append(args, *filter.NodeID)
		conditions = append(conditions, "ingress_node_id = $"+strconv.Itoa(len(args)))
	}
	if filter.Mode != nil {
		args = append(args, *filter.Mode)
		conditions = append(conditions, "mode = $"+strconv.Itoa(len(args)))
	}
	if filter.Status != nil {
		args = append(args, *filter.Status)
		conditions = append(conditions, "status = $"+strconv.Itoa(len(args)))
	}
	if filter.SyncStatus != nil {
		args = append(args, *filter.SyncStatus)
		conditions = append(conditions, "sync_status = $"+strconv.Itoa(len(args)))
	}

	query := `SELECT COUNT(*) FROM forwarding_rules`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}

	return total, nil
}

func (s *RuleService) userMaxRules(ctx context.Context, userID uuid.UUID) (int, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return 0, ErrUserNotFound
		}
		return 0, err
	}
	return user.MaxRules, nil
}

func (s *RuleService) loadSystemDefaults(ctx context.Context) (NodePassParams, error) {
	if s.pool == nil {
		return NodePassParams{}, nil
	}

	var raw string
	err := s.pool.QueryRow(
		ctx,
		`SELECT COALESCE(telegram_config->'nodepass_defaults', '{}'::jsonb)::text
		 FROM system_configs
		 WHERE id = 1`,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return NodePassParams{}, nil
		}
		return NodePassParams{}, err
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return NodePassParams{}, nil
	}

	return parseNodePassParams(decoded), nil
}

func (s *RuleService) updateRuleInstanceInfo(ctx context.Context, ruleID uuid.UUID, patch map[string]interface{}) error {
	if s.pool == nil || len(patch) == 0 {
		return nil
	}

	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(
		ctx,
		`UPDATE forwarding_rules
		 SET instance_info = COALESCE(instance_info, '{}'::jsonb) || $2::jsonb,
		     updated_at = NOW()
		 WHERE id = $1`,
		ruleID,
		raw,
	)
	return err
}

func (s *RuleService) emitRuleStatus(rule *model.ForwardingRule, action, status, syncStatus string, actionErr error) {
	if s.sseHub == nil || rule == nil {
		return
	}

	payload := map[string]interface{}{
		"rule_id":      rule.ID.String(),
		"action":       action,
		"status":       status,
		"sync_status":  syncStatus,
		"owner_id":     rule.OwnerID.String(),
		"ingress_node": rule.IngressNodeID.String(),
		"ts":           time.Now().UTC().Format(time.RFC3339Nano),
	}
	if actionErr != nil {
		payload["error"] = actionErr.Error()
	}
	event := sse.NewEvent(sse.EventRuleStatus, payload)
	s.sseHub.SendToUser(rule.OwnerID.String(), event)
	s.sseHub.SendToRole(string(model.UserRoleAdmin), event)
}

func (s *RuleService) writeAudit(
	ctx context.Context,
	operatorID string,
	action string,
	resourceID string,
	oldValue map[string]interface{},
	newValue map[string]interface{},
) {
	if s.auditRepo == nil {
		return
	}

	var actorID *uuid.UUID
	if strings.TrimSpace(operatorID) != "" {
		if parsed, err := uuid.Parse(strings.TrimSpace(operatorID)); err == nil {
			actorID = &parsed
		}
	}

	_ = s.auditRepo.Create(ctx, &model.AuditLog{
		UserID:       actorID,
		Action:       action,
		ResourceType: strPtr(ruleResourceTypeName),
		ResourceID:   strPtr(resourceID),
		OldValue:     oldValue,
		NewValue:     newValue,
		CreatedAt:    time.Now().UTC(),
	})
}

func (s *RuleService) applyUserBandwidthLimit(ctx context.Context, ownerID uuid.UUID, params *NodePassParams) error {
	if params == nil || s.userRepo == nil {
		return nil
	}

	user, err := s.userRepo.FindByID(ctx, ownerID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil
		}
		return err
	}
	if user == nil || user.BandwidthLimit <= 0 {
		return nil
	}

	rate := clampInt64ToInt(user.BandwidthLimit)
	params.Rate = &rate
	return nil
}

func clampInt64ToInt(value int64) int {
	if value <= 0 {
		return 0
	}

	maxInt := int64(^uint(0) >> 1)
	if value > maxInt {
		return int(maxInt)
	}
	return int(value)
}

func nodePassParamsFromCreateRequest(req CreateRuleRequest) NodePassParams {
	return NodePassParams{
		TLS:   req.NpTLS,
		Mode:  req.NpMode,
		Min:   req.NpMin,
		Max:   req.NpMax,
		Rate:  req.NpRate,
		NoTCP: req.NpNoTCP,
		NoUDP: req.NpNoUDP,
		Log:   req.NpLog,
	}
}

func modelNpParamsToNodePass(params model.NpParams) NodePassParams {
	return NodePassParams{
		TLS:   params.NpTLS,
		Mode:  params.NpMode,
		Min:   params.NpMin,
		Max:   params.NpMax,
		Rate:  params.NpRate,
		NoTCP: params.NpNoTCP,
		NoUDP: params.NpNoUDP,
		Log:   params.NpLog,
	}
}

func toModelNpParams(params NodePassParams) model.NpParams {
	return model.NpParams{
		NpTLS:   params.TLS,
		NpMode:  params.Mode,
		NpMin:   params.Min,
		NpMax:   params.Max,
		NpRate:  params.Rate,
		NpNoTCP: params.NoTCP,
		NpNoUDP: params.NoUDP,
		NpLog:   params.Log,
	}
}

func applyNodePassOverride(params *NodePassParams, req UpdateRuleRequest) {
	if params == nil {
		return
	}
	if req.NpTLS != nil {
		params.TLS = req.NpTLS
	}
	if req.NpMode != nil {
		params.Mode = req.NpMode
	}
	if req.NpMin != nil {
		params.Min = req.NpMin
	}
	if req.NpMax != nil {
		params.Max = req.NpMax
	}
	if req.NpRate != nil {
		params.Rate = req.NpRate
	}
	if req.NpNoTCP != nil {
		params.NoTCP = req.NpNoTCP
	}
	if req.NpNoUDP != nil {
		params.NoUDP = req.NpNoUDP
	}
	if req.NpLog != nil {
		params.Log = req.NpLog
	}
}

func parseNodeDefaultsFromNode(node *model.NodeAgent) NodePassParams {
	if node == nil {
		return NodePassParams{}
	}

	raw, ok := node.SysInfo["nodepass_defaults"]
	if !ok {
		return NodePassParams{}
	}

	defaultsMap, ok := raw.(map[string]interface{})
	if !ok {
		return NodePassParams{}
	}

	return parseNodePassParams(defaultsMap)
}

func parseNodePassParams(raw map[string]interface{}) NodePassParams {
	params := NodePassParams{}

	if value, ok := mapInt(raw, "tls"); ok {
		params.TLS = &value
	}
	if value, ok := mapString(raw, "mode"); ok {
		params.Mode = &value
	}
	if value, ok := mapInt(raw, "min"); ok {
		params.Min = &value
	}
	if value, ok := mapInt(raw, "max"); ok {
		params.Max = &value
	}
	if value, ok := mapInt(raw, "rate"); ok {
		params.Rate = &value
	}
	if value, ok := mapBool(raw, "notcp"); ok {
		params.NoTCP = &value
	}
	if value, ok := mapBool(raw, "noudp"); ok {
		params.NoUDP = &value
	}
	if value, ok := mapString(raw, "log"); ok {
		params.Log = &value
	}

	return params
}

func nextRuleStatus(action string, current string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case ruleActionStart, ruleActionRestart:
		return ruleStatusRunning
	case ruleActionStop:
		return ruleStatusStopped
	case ruleActionSync:
		return current
	default:
		return current
	}
}

func normalizeRuleListPage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = ruleListDefaultPage
	}
	if pageSize <= 0 {
		pageSize = ruleListDefaultSize
	}
	if pageSize > ruleListMaxPageSize {
		pageSize = ruleListMaxPageSize
	}
	return page, pageSize
}

func isSupportedRuleMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "single", "tunnel", "lb", "hop_chain":
		return true
	default:
		return false
	}
}

func parseOptionalUUID(raw string) (*uuid.UUID, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	value, err := uuid.Parse(trimmed)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func parseOptionalUUIDPtr(raw *string) (*uuid.UUID, error) {
	if raw == nil {
		return nil, nil
	}
	return parseOptionalUUID(*raw)
}

func mapInt(raw map[string]interface{}, key string) (int, bool) {
	value, ok := raw[key]
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func mapString(raw map[string]interface{}, key string) (string, bool) {
	value, ok := raw[key]
	if !ok {
		return "", false
	}
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			return trimmed, true
		}
	}
	return "", false
}

func mapBool(raw map[string]interface{}, key string) (bool, bool) {
	value, ok := raw[key]
	if !ok {
		return false, false
	}
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err == nil {
			return parsed, true
		}
	}
	return false, false
}

func cloneMap(input map[string]interface{}) map[string]interface{} {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
