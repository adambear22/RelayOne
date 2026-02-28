package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

const (
	hopListDefaultPage = 1
	hopListDefaultSize = 20
	hopListMaxPageSize = 200
)

const (
	hopActionStart = "start"
	hopActionStop  = "stop"
)

const (
	hopRuleSyncSynced = "synced"
	hopRuleSyncFailed = "sync_failed"
)

var (
	ErrHopChainNotFound     = errors.New("hop chain not found")
	ErrHopChainNodeNotFound = errors.New("hop chain node not found")
	ErrInvalidHopChainInput = errors.New("invalid hop chain input")
	ErrHopChainDispatch     = errors.New("hop chain dispatch failed")
	ErrHopChainEmpty        = errors.New("hop chain has no nodes")
	ErrHopChainNodeOffline  = errors.New("hop chain node offline")
	ErrHopChainInvalidOrder = errors.New("invalid hop chain order")
)

type hopChainCommandHub interface {
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

type CreateHopChainRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

type UpdateHopChainRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type HopChainNodeInput struct {
	ID               *string                `json:"id,omitempty"`
	NodeID           string                 `json:"node_id"`
	HopOrder         int                    `json:"hop_order"`
	NpParamsOverride map[string]interface{} `json:"np_params_override,omitempty"`
}

type HopChainNodeReorderItem struct {
	ID       string `json:"id"`
	HopOrder int    `json:"hop_order"`
}

type hopDispatchStep struct {
	NodeID      string
	NodePassURL string
	Target      string
}

type HopChainService struct {
	pool     *pgxpool.Pool
	ruleRepo repository.RuleRepository
	nodeRepo repository.NodeRepository
	hub      hopChainCommandHub
	logger   *zap.Logger
}

func NewHopChainService(
	pool *pgxpool.Pool,
	ruleRepo repository.RuleRepository,
	nodeRepo repository.NodeRepository,
	hub hopChainCommandHub,
	logger *zap.Logger,
) *HopChainService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &HopChainService{
		pool:     pool,
		ruleRepo: ruleRepo,
		nodeRepo: nodeRepo,
		hub:      hub,
		logger:   logger,
	}
}

func (s *HopChainService) Create(ctx context.Context, ownerID string, req CreateHopChainRequest) (*model.HopChain, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	ownerUUID, err := uuid.Parse(strings.TrimSpace(ownerID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrInvalidHopChainInput
	}

	chain := &model.HopChain{
		ID:          uuid.New(),
		Name:        name,
		OwnerID:     &ownerUUID,
		Description: trimStringPtr(req.Description),
		CreatedAt:   time.Now().UTC(),
	}

	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO hop_chains (id, name, owner_id, description, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		chain.ID,
		chain.Name,
		chain.OwnerID,
		chain.Description,
		chain.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return chain, nil
}

func (s *HopChainService) GetByID(ctx context.Context, chainID string) (*model.HopChain, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	chainUUID, err := uuid.Parse(strings.TrimSpace(chainID))
	if err != nil {
		return nil, ErrInvalidHopChainInput
	}

	return s.findChainByID(ctx, chainUUID)
}

func (s *HopChainService) List(
	ctx context.Context,
	page, pageSize int,
	ownerID *string,
) ([]*model.HopChain, int64, error) {
	if s.pool == nil {
		return nil, 0, errors.New("database pool is nil")
	}

	page, pageSize = normalizeHopPagination(page, pageSize)
	args := make([]any, 0, 4)
	conditions := make([]string, 0, 1)
	if ownerID != nil && strings.TrimSpace(*ownerID) != "" {
		ownerUUID, err := uuid.Parse(strings.TrimSpace(*ownerID))
		if err != nil {
			return nil, 0, ErrInvalidUserID
		}
		args = append(args, ownerUUID)
		conditions = append(conditions, fmt.Sprintf("owner_id = $%d", len(args)))
	}

	query := `SELECT id, name, owner_id, description, created_at FROM hop_chains`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	args = append(args, pageSize, (page-1)*pageSize)
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]*model.HopChain, 0, pageSize)
	for rows.Next() {
		item, scanErr := scanHopChain(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	countQuery := `SELECT COUNT(*) FROM hop_chains`
	if len(conditions) > 0 {
		countQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	if err := s.pool.QueryRow(ctx, countQuery, args[:len(args)-2]...).Scan(&total); err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *HopChainService) Update(ctx context.Context, chainID string, req UpdateHopChainRequest) (*model.HopChain, error) {
	chain, err := s.GetByID(ctx, chainID)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return nil, ErrInvalidHopChainInput
		}
		chain.Name = name
	}
	if req.Description != nil {
		chain.Description = trimStringPtr(req.Description)
	}

	tag, err := s.pool.Exec(
		ctx,
		`UPDATE hop_chains
		    SET name = $2,
		        description = $3
		  WHERE id = $1`,
		chain.ID,
		chain.Name,
		chain.Description,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrHopChainNotFound
	}

	return chain, nil
}

func (s *HopChainService) Delete(ctx context.Context, chainID string) error {
	chainUUID, err := uuid.Parse(strings.TrimSpace(chainID))
	if err != nil {
		return ErrInvalidHopChainInput
	}

	tag, err := s.pool.Exec(ctx, `DELETE FROM hop_chains WHERE id = $1`, chainUUID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrHopChainNotFound
	}

	return nil
}

func (s *HopChainService) ListNodes(ctx context.Context, chainID string) ([]*model.HopChainNode, error) {
	chainUUID, err := uuid.Parse(strings.TrimSpace(chainID))
	if err != nil {
		return nil, ErrInvalidHopChainInput
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT id, chain_id, hop_order, node_id, np_params_override
		   FROM hop_chain_nodes
		  WHERE chain_id = $1
		  ORDER BY hop_order ASC`,
		chainUUID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*model.HopChainNode, 0, 8)
	for rows.Next() {
		item, scanErr := scanHopChainNode(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func (s *HopChainService) ReplaceNodes(ctx context.Context, chainID string, nodes []HopChainNodeInput) error {
	if len(nodes) == 0 {
		return ErrInvalidHopChainInput
	}

	chainUUID, err := uuid.Parse(strings.TrimSpace(chainID))
	if err != nil {
		return ErrInvalidHopChainInput
	}

	if err := s.validateNodeInputs(ctx, nodes); err != nil {
		return err
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `DELETE FROM hop_chain_nodes WHERE chain_id = $1`, chainUUID); err != nil {
		return err
	}

	for _, input := range nodes {
		nodeUUID, _ := uuid.Parse(strings.TrimSpace(input.NodeID))

		overrideRaw, err := json.Marshal(input.NpParamsOverride)
		if err != nil {
			return err
		}

		if _, err := tx.Exec(
			ctx,
			`INSERT INTO hop_chain_nodes (id, chain_id, hop_order, node_id, np_params_override)
			 VALUES ($1, $2, $3, $4, $5)`,
			uuid.New(),
			chainUUID,
			input.HopOrder,
			nodeUUID,
			overrideRaw,
		); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *HopChainService) ReorderNodes(ctx context.Context, chainID string, updates []HopChainNodeReorderItem) error {
	if len(updates) == 0 {
		return ErrInvalidHopChainInput
	}

	chainUUID, err := uuid.Parse(strings.TrimSpace(chainID))
	if err != nil {
		return ErrInvalidHopChainInput
	}

	orders := make(map[int]struct{}, len(updates))
	ids := make([]uuid.UUID, 0, len(updates))
	for _, item := range updates {
		if item.HopOrder <= 0 {
			return ErrHopChainInvalidOrder
		}
		if _, exists := orders[item.HopOrder]; exists {
			return ErrHopChainInvalidOrder
		}
		orders[item.HopOrder] = struct{}{}

		id, parseErr := uuid.Parse(strings.TrimSpace(item.ID))
		if parseErr != nil {
			return ErrInvalidHopChainInput
		}
		ids = append(ids, id)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for idx, id := range ids {
		tempOrder := -(idx + 1)
		tag, err := tx.Exec(
			ctx,
			`UPDATE hop_chain_nodes
			    SET hop_order = $3
			  WHERE chain_id = $1
			    AND id = $2`,
			chainUUID,
			id,
			tempOrder,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrHopChainNodeNotFound
		}
	}

	for _, item := range updates {
		id, _ := uuid.Parse(strings.TrimSpace(item.ID))
		if _, err := tx.Exec(
			ctx,
			`UPDATE hop_chain_nodes
			    SET hop_order = $3
			  WHERE chain_id = $1
			    AND id = $2`,
			chainUUID,
			id,
			item.HopOrder,
		); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *HopChainService) IsOwner(ctx context.Context, chainID string, userID string) (bool, error) {
	chainUUID, err := uuid.Parse(strings.TrimSpace(chainID))
	if err != nil {
		return false, ErrInvalidHopChainInput
	}
	userUUID, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return false, ErrInvalidUserID
	}

	var ownerID *uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT owner_id FROM hop_chains WHERE id = $1`, chainUUID).Scan(&ownerID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrHopChainNotFound
		}
		return false, err
	}

	return ownerID != nil && *ownerID == userUUID, nil
}

func (s *HopChainService) DispatchHopChain(ctx context.Context, chainID, ruleID string) error {
	if s.hub == nil {
		return errors.New("hop chain command hub is nil")
	}

	chainUUID, err := uuid.Parse(strings.TrimSpace(chainID))
	if err != nil {
		return ErrInvalidHopChainInput
	}
	ruleUUID, err := uuid.Parse(strings.TrimSpace(ruleID))
	if err != nil {
		return ErrInvalidRuleID
	}

	nodes, err := s.ListNodes(ctx, chainUUID.String())
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return ErrHopChainEmpty
	}

	rule, err := s.ruleRepo.FindByID(ctx, ruleUUID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrRuleNotFound
		}
		return err
	}

	nodeAgents := make([]*model.NodeAgent, 0, len(nodes))
	for _, chainNode := range nodes {
		node, err := s.nodeRepo.FindByID(ctx, chainNode.NodeID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return ErrNodeNotFound
			}
			return err
		}
		if !strings.EqualFold(strings.TrimSpace(node.Status), "online") {
			return ErrHopChainNodeOffline
		}
		nodeAgents = append(nodeAgents, node)
	}

	systemDefaults, _ := s.loadSystemDefaults(ctx)
	baseOverride := ruleNpParamsToNodePass(rule.NpParams)

	started := make([]hopDispatchStep, 0, len(nodes))
	for idx, chainNode := range nodes {
		current := nodeAgents[idx]

		instanceType := "peer"
		switch {
		case idx == 0:
			instanceType = "server"
		case idx == len(nodes)-1:
			instanceType = "client"
		}

		targetHost := rule.TargetHost
		targetPort := rule.TargetPort
		if idx < len(nodes)-1 {
			targetHost = nodeAgents[idx+1].Host
			targetPort = nodeAgents[idx+1].APIPort
		}

		nodeDefaults := parseNodePassDefaultsFromSysInfo(current.SysInfo)
		hopOverride := parseNodePassParamsMap(chainNode.NpParamsOverride)
		override := mergeNodePassParams(baseOverride, hopOverride)
		params := Compile(systemDefaults, nodeDefaults, override)
		if err := Validate(params); err != nil {
			return err
		}

		nodepassURL := BuildURL(instanceType, targetHost, targetPort, "", "", params)
		target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))

		acked, sendErr := s.hub.SendConfigPushAndWaitAck(
			ctx,
			current.ID.String(),
			rule.ID.String(),
			hopActionStart,
			nodepassURL,
			target,
			10*time.Second,
		)
		if sendErr != nil || !acked {
			_ = s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, hopRuleSyncFailed)
			s.stopStartedHops(rule.ID.String(), started)
			if sendErr != nil {
				return sendErr
			}
			return ErrRuleSyncTimeout
		}

		started = append(started, hopDispatchStep{
			NodeID:      current.ID.String(),
			NodePassURL: nodepassURL,
			Target:      target,
		})
	}

	if err := s.ruleRepo.UpdateSyncStatus(ctx, rule.ID, hopRuleSyncSynced); err != nil {
		return err
	}

	return nil
}

func (s *HopChainService) stopStartedHops(ruleID string, started []hopDispatchStep) {
	if s.hub == nil || len(started) == 0 {
		return
	}

	for i := len(started) - 1; i >= 0; i-- {
		step := started[i]
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := s.hub.SendConfigPushAndWaitAck(
			ctx,
			step.NodeID,
			ruleID,
			hopActionStop,
			step.NodePassURL,
			step.Target,
			3*time.Second,
		)
		cancel()
		if err != nil {
			s.logger.Warn("rollback hop chain step failed",
				zap.String("rule_id", ruleID),
				zap.String("node_id", step.NodeID),
				zap.Error(err),
			)
		}
	}
}

func (s *HopChainService) validateNodeInputs(ctx context.Context, nodes []HopChainNodeInput) error {
	orders := make(map[int]struct{}, len(nodes))
	for _, node := range nodes {
		if node.HopOrder <= 0 {
			return ErrHopChainInvalidOrder
		}
		if _, exists := orders[node.HopOrder]; exists {
			return ErrHopChainInvalidOrder
		}
		orders[node.HopOrder] = struct{}{}

		nodeUUID, err := uuid.Parse(strings.TrimSpace(node.NodeID))
		if err != nil {
			return ErrInvalidNodeID
		}
		if _, err := s.nodeRepo.FindByID(ctx, nodeUUID); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return ErrNodeNotFound
			}
			return err
		}
	}

	return nil
}

func (s *HopChainService) findChainByID(ctx context.Context, chainID uuid.UUID) (*model.HopChain, error) {
	item, err := scanHopChain(s.pool.QueryRow(
		ctx,
		`SELECT id, name, owner_id, description, created_at
		   FROM hop_chains
		  WHERE id = $1`,
		chainID,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrHopChainNotFound
		}
		return nil, err
	}
	return item, nil
}

func (s *HopChainService) loadSystemDefaults(ctx context.Context) (NodePassParams, error) {
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

	decoded := make(map[string]interface{})
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return NodePassParams{}, nil
	}

	return parseNodePassParamsMap(decoded), nil
}

func parseNodePassDefaultsFromSysInfo(sysInfo map[string]interface{}) NodePassParams {
	if len(sysInfo) == 0 {
		return NodePassParams{}
	}
	raw, ok := sysInfo["nodepass_defaults"]
	if !ok {
		return NodePassParams{}
	}
	mapped, ok := raw.(map[string]interface{})
	if !ok {
		return NodePassParams{}
	}
	return parseNodePassParamsMap(mapped)
}

func parseNodePassParamsMap(raw map[string]interface{}) NodePassParams {
	params := NodePassParams{}
	if raw == nil {
		return params
	}

	if value, ok := anyToInt(raw["tls"]); ok {
		params.TLS = &value
	}
	if value, ok := anyToString(raw["mode"]); ok {
		params.Mode = &value
	}
	if value, ok := anyToInt(raw["min"]); ok {
		params.Min = &value
	}
	if value, ok := anyToInt(raw["max"]); ok {
		params.Max = &value
	}
	if value, ok := anyToInt(raw["rate"]); ok {
		params.Rate = &value
	}
	if value, ok := anyToBool(raw["notcp"]); ok {
		params.NoTCP = &value
	}
	if value, ok := anyToBool(raw["noudp"]); ok {
		params.NoUDP = &value
	}
	if value, ok := anyToString(raw["log"]); ok {
		params.Log = &value
	}

	return params
}

func mergeNodePassParams(base NodePassParams, override NodePassParams) NodePassParams {
	merged := base
	if override.TLS != nil {
		merged.TLS = override.TLS
	}
	if override.Mode != nil {
		merged.Mode = override.Mode
	}
	if override.Min != nil {
		merged.Min = override.Min
	}
	if override.Max != nil {
		merged.Max = override.Max
	}
	if override.Rate != nil {
		merged.Rate = override.Rate
	}
	if override.NoTCP != nil {
		merged.NoTCP = override.NoTCP
	}
	if override.NoUDP != nil {
		merged.NoUDP = override.NoUDP
	}
	if override.Log != nil {
		merged.Log = override.Log
	}
	return merged
}

func ruleNpParamsToNodePass(params model.NpParams) NodePassParams {
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

func scanHopChain(src rowScanner) (*model.HopChain, error) {
	item := &model.HopChain{}
	if err := src.Scan(
		&item.ID,
		&item.Name,
		&item.OwnerID,
		&item.Description,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	return item, nil
}

func scanHopChainNode(src rowScanner) (*model.HopChainNode, error) {
	item := &model.HopChainNode{}
	var overrideRaw []byte
	if err := src.Scan(
		&item.ID,
		&item.ChainID,
		&item.HopOrder,
		&item.NodeID,
		&overrideRaw,
	); err != nil {
		return nil, err
	}

	if len(overrideRaw) > 0 {
		if err := json.Unmarshal(overrideRaw, &item.NpParamsOverride); err != nil {
			return nil, err
		}
	}

	return item, nil
}

func normalizeHopPagination(page, pageSize int) (int, int) {
	if page <= 0 {
		page = hopListDefaultPage
	}
	if pageSize <= 0 {
		pageSize = hopListDefaultSize
	}
	if pageSize > hopListMaxPageSize {
		pageSize = hopListMaxPageSize
	}
	return page, pageSize
}

func trimStringPtr(v *string) *string {
	if v == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*v)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func anyToInt(v interface{}) (int, bool) {
	switch value := v.(type) {
	case int:
		return value, true
	case int8:
		return int(value), true
	case int16:
		return int(value), true
	case int32:
		return int(value), true
	case int64:
		return int(value), true
	case float32:
		return int(value), true
	case float64:
		return int(value), true
	case json.Number:
		parsed, err := strconv.Atoi(value.String())
		if err != nil {
			return 0, false
		}
		return parsed, true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func anyToString(v interface{}) (string, bool) {
	switch value := v.(type) {
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return "", false
		}
		return trimmed, true
	default:
		return "", false
	}
}

func anyToBool(v interface{}) (bool, bool) {
	switch value := v.(type) {
	case bool:
		return value, true
	case string:
		trimmed := strings.TrimSpace(strings.ToLower(value))
		switch trimmed {
		case "1", "true", "yes":
			return true, true
		case "0", "false", "no":
			return false, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}
