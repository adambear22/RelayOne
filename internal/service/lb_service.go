package service

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/sse"
)

const (
	lbListDefaultPage  = 1
	lbListDefaultSize  = 20
	lbListMaxPageSize  = 200
	lbHealthTickPeriod = 5 * time.Second
)

var (
	ErrLBGroupNotFound   = errors.New("lb group not found")
	ErrLBMemberNotFound  = errors.New("lb group member not found")
	ErrLBNoActiveMembers = errors.New("lb group has no active members")
	ErrInvalidLBInput    = errors.New("invalid lb input")
)

type Selector interface {
	Select(clientIP string) (*model.LBGroupMember, error)
}

type RoundRobinSelector struct {
	members []*model.LBGroupMember
	counter atomic.Int64
}

type LeastConnSelector struct {
	members    []*model.LBGroupMember
	connCounts sync.Map
}

type RandomSelector struct {
	members []*model.LBGroupMember
	rnd     *rand.Rand
	mu      sync.Mutex
}

type IPHashSelector struct {
	members []*model.LBGroupMember
}

type AgentPinger interface {
	PingAgent(ctx context.Context, agentID string, timeout time.Duration) error
}

type CreateLBGroupRequest struct {
	Name                string `json:"name"`
	Strategy            string `json:"strategy"`
	HealthCheckInterval int    `json:"health_check_interval"`
}

type UpdateLBGroupRequest struct {
	Name                *string `json:"name"`
	Strategy            *string `json:"strategy"`
	HealthCheckInterval *int    `json:"health_check_interval"`
}

type CreateLBGroupMemberRequest struct {
	NodeID   string `json:"node_id"`
	Weight   int    `json:"weight"`
	IsActive *bool  `json:"is_active"`
}

type UpdateLBGroupMemberRequest struct {
	Weight   *int  `json:"weight"`
	IsActive *bool `json:"is_active"`
}

type lbSelectorCache struct {
	Group   *model.LBGroup
	Members []*model.LBGroupMember
	Select  Selector
}

type LBService struct {
	pool     *pgxpool.Pool
	nodeRepo repository.NodeRepository
	hub      AgentPinger
	sseHub   *sse.SSEHub
	logger   *zap.Logger

	selectorCache sync.Map
	lastHealthRun sync.Map
	stopCh        chan struct{}
	stopOnce      sync.Once
}

func NewLBService(
	pool *pgxpool.Pool,
	nodeRepo repository.NodeRepository,
	hub AgentPinger,
	sseHub *sse.SSEHub,
	logger *zap.Logger,
) *LBService {
	if logger == nil {
		logger = zap.NewNop()
	}

	s := &LBService{
		pool:     pool,
		nodeRepo: nodeRepo,
		hub:      hub,
		sseHub:   sseHub,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}

	go s.healthCheckLoop()

	return s
}

func (s *LBService) Close() {
	if s == nil {
		return
	}

	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

func NewSelector(strategy string, members []*model.LBGroupMember) Selector {
	normalized := strings.ToLower(strings.TrimSpace(strategy))
	switch normalized {
	case "least_conn":
		return &LeastConnSelector{members: members}
	case "random":
		return &RandomSelector{
			members: members,
			rnd:     rand.New(rand.NewSource(time.Now().UnixNano())),
		}
	case "ip_hash":
		return &IPHashSelector{members: members}
	case "round_robin":
		fallthrough
	default:
		return &RoundRobinSelector{members: members}
	}
}

func (s *RoundRobinSelector) Select(_ string) (*model.LBGroupMember, error) {
	active := activeMembers(s.members)
	if len(active) == 0 {
		return nil, ErrLBNoActiveMembers
	}

	idx := int((s.counter.Add(1) - 1) % int64(len(active)))
	return active[idx], nil
}

func (s *LeastConnSelector) Select(_ string) (*model.LBGroupMember, error) {
	active := activeMembers(s.members)
	if len(active) == 0 {
		return nil, ErrLBNoActiveMembers
	}

	selected := active[0]
	min := s.getConnCounter(selected.NodeID).Load()
	for _, member := range active[1:] {
		count := s.getConnCounter(member.NodeID).Load()
		if count < min {
			min = count
			selected = member
		}
	}

	s.getConnCounter(selected.NodeID).Add(1)
	return selected, nil
}

func (s *LeastConnSelector) getConnCounter(nodeID uuid.UUID) *atomic.Int64 {
	key := nodeID.String()
	if current, ok := s.connCounts.Load(key); ok {
		if counter, valid := current.(*atomic.Int64); valid {
			return counter
		}
	}

	counter := &atomic.Int64{}
	current, _ := s.connCounts.LoadOrStore(key, counter)
	if cast, ok := current.(*atomic.Int64); ok {
		return cast
	}
	return counter
}

func (s *RandomSelector) Select(_ string) (*model.LBGroupMember, error) {
	active := activeMembers(s.members)
	if len(active) == 0 {
		return nil, ErrLBNoActiveMembers
	}

	s.mu.Lock()
	idx := s.rnd.Intn(len(active))
	s.mu.Unlock()

	return active[idx], nil
}

func (s *IPHashSelector) Select(clientIP string) (*model.LBGroupMember, error) {
	active := activeMembers(s.members)
	if len(active) == 0 {
		return nil, ErrLBNoActiveMembers
	}

	trimmedIP := parseIPHashInput(clientIP)
	if trimmedIP == "" {
		return active[0], nil
	}

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(trimmedIP))
	idx := int(hasher.Sum32() % uint32(len(active)))
	return active[idx], nil
}

func (s *LBService) SelectEgress(ctx context.Context, groupID, clientIP string) (*model.NodeAgent, error) {
	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return nil, ErrInvalidLBInput
	}

	cache, err := s.getSelectorCache(ctx, groupUUID)
	if err != nil {
		return nil, err
	}

	membersCount := len(cache.Members)
	if membersCount == 0 {
		return nil, ErrLBNoActiveMembers
	}

	for attempt := 0; attempt < membersCount; attempt++ {
		member, err := cache.Select.Select(clientIP)
		if err != nil {
			return nil, err
		}
		if member == nil {
			continue
		}

		node, err := s.nodeRepo.FindByID(ctx, member.NodeID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				_ = s.SetMemberActive(ctx, cache.Group.ID.String(), member.ID.String(), false)
				continue
			}
			return nil, err
		}

		if strings.EqualFold(node.Status, "online") {
			return node, nil
		}

		_ = s.SetMemberActive(ctx, cache.Group.ID.String(), member.ID.String(), false)
	}

	return nil, ErrLBNoActiveMembers
}

func (s *LBService) CreateGroup(ctx context.Context, ownerID string, req CreateLBGroupRequest) (*model.LBGroup, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	ownerUUID, err := uuid.Parse(strings.TrimSpace(ownerID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrInvalidLBInput
	}

	group := &model.LBGroup{
		ID:                  uuid.New(),
		Name:                name,
		OwnerID:             &ownerUUID,
		Strategy:            normalizeLBStrategy(req.Strategy),
		HealthCheckInterval: normalizeHealthInterval(req.HealthCheckInterval),
		CreatedAt:           time.Now().UTC(),
	}

	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO lb_groups (id, name, owner_id, strategy, health_check_interval, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		group.ID,
		group.Name,
		group.OwnerID,
		group.Strategy,
		group.HealthCheckInterval,
		group.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (s *LBService) GetGroup(ctx context.Context, groupID string) (*model.LBGroup, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return nil, ErrInvalidLBInput
	}

	return s.findGroupByID(ctx, groupUUID)
}

func (s *LBService) ListGroups(
	ctx context.Context,
	page, pageSize int,
	ownerID *string,
) ([]*model.LBGroup, int64, error) {
	if s.pool == nil {
		return nil, 0, errors.New("database pool is nil")
	}

	page, pageSize = normalizeLBPagination(page, pageSize)

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

	query := `SELECT id, name, owner_id, strategy, health_check_interval, created_at FROM lb_groups`
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

	items := make([]*model.LBGroup, 0, pageSize)
	for rows.Next() {
		item, scanErr := scanLBGroup(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	countQuery := `SELECT COUNT(*) FROM lb_groups`
	if len(conditions) > 0 {
		countQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	if err := s.pool.QueryRow(ctx, countQuery, args[:len(args)-2]...).Scan(&total); err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *LBService) UpdateGroup(ctx context.Context, groupID string, req UpdateLBGroupRequest) (*model.LBGroup, error) {
	group, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			return nil, ErrInvalidLBInput
		}
		group.Name = trimmed
	}
	if req.Strategy != nil {
		group.Strategy = normalizeLBStrategy(*req.Strategy)
	}
	if req.HealthCheckInterval != nil {
		group.HealthCheckInterval = normalizeHealthInterval(*req.HealthCheckInterval)
	}

	tag, err := s.pool.Exec(
		ctx,
		`UPDATE lb_groups
		    SET name = $2,
		        strategy = $3,
		        health_check_interval = $4
		  WHERE id = $1`,
		group.ID,
		group.Name,
		group.Strategy,
		group.HealthCheckInterval,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrLBGroupNotFound
	}

	s.selectorCache.Delete(group.ID.String())
	return group, nil
}

func (s *LBService) DeleteGroup(ctx context.Context, groupID string) error {
	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return ErrInvalidLBInput
	}

	tag, err := s.pool.Exec(ctx, `DELETE FROM lb_groups WHERE id = $1`, groupUUID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLBGroupNotFound
	}

	s.selectorCache.Delete(groupUUID.String())
	return nil
}

func (s *LBService) ListMembers(ctx context.Context, groupID string) ([]*model.LBGroupMember, error) {
	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return nil, ErrInvalidLBInput
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT id, group_id, node_id, weight, is_active, created_at
		   FROM lb_group_members
		  WHERE group_id = $1
		  ORDER BY created_at ASC`,
		groupUUID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*model.LBGroupMember, 0, 16)
	for rows.Next() {
		item, scanErr := scanLBGroupMember(rows)
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

func (s *LBService) AddMember(ctx context.Context, groupID string, req CreateLBGroupMemberRequest) (*model.LBGroupMember, error) {
	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return nil, ErrInvalidLBInput
	}

	nodeUUID, err := uuid.Parse(strings.TrimSpace(req.NodeID))
	if err != nil {
		return nil, ErrInvalidNodeID
	}
	if _, err := s.nodeRepo.FindByID(ctx, nodeUUID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}

	weight := req.Weight
	if weight <= 0 {
		weight = 1
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	member := &model.LBGroupMember{
		ID:        uuid.New(),
		GroupID:   groupUUID,
		NodeID:    nodeUUID,
		Weight:    weight,
		IsActive:  isActive,
		CreatedAt: time.Now().UTC(),
	}

	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO lb_group_members (id, group_id, node_id, weight, is_active, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		member.ID,
		member.GroupID,
		member.NodeID,
		member.Weight,
		member.IsActive,
		member.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	s.selectorCache.Delete(groupUUID.String())
	return member, nil
}

func (s *LBService) UpdateMember(
	ctx context.Context,
	groupID string,
	memberID string,
	req UpdateLBGroupMemberRequest,
) (*model.LBGroupMember, error) {
	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return nil, ErrInvalidLBInput
	}
	memberUUID, err := uuid.Parse(strings.TrimSpace(memberID))
	if err != nil {
		return nil, ErrInvalidLBInput
	}

	member, err := s.findMemberByID(ctx, groupUUID, memberUUID)
	if err != nil {
		return nil, err
	}

	if req.Weight != nil {
		if *req.Weight <= 0 {
			return nil, ErrInvalidLBInput
		}
		member.Weight = *req.Weight
	}
	if req.IsActive != nil {
		member.IsActive = *req.IsActive
	}

	tag, err := s.pool.Exec(
		ctx,
		`UPDATE lb_group_members
		    SET weight = $3,
		        is_active = $4
		  WHERE id = $1
		    AND group_id = $2`,
		member.ID,
		member.GroupID,
		member.Weight,
		member.IsActive,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrLBMemberNotFound
	}

	s.updateCachedMemberState(member.ID, member.IsActive)
	return member, nil
}

func (s *LBService) DeleteMember(ctx context.Context, groupID string, memberID string) error {
	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return ErrInvalidLBInput
	}
	memberUUID, err := uuid.Parse(strings.TrimSpace(memberID))
	if err != nil {
		return ErrInvalidLBInput
	}

	tag, err := s.pool.Exec(
		ctx,
		`DELETE FROM lb_group_members
		  WHERE id = $1
		    AND group_id = $2`,
		memberUUID,
		groupUUID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLBMemberNotFound
	}

	s.selectorCache.Delete(groupUUID.String())
	return nil
}

func (s *LBService) SetMemberActive(ctx context.Context, groupID, memberID string, active bool) error {
	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return ErrInvalidLBInput
	}
	memberUUID, err := uuid.Parse(strings.TrimSpace(memberID))
	if err != nil {
		return ErrInvalidLBInput
	}

	tag, err := s.pool.Exec(
		ctx,
		`UPDATE lb_group_members
		    SET is_active = $3
		  WHERE id = $1
		    AND group_id = $2`,
		memberUUID,
		groupUUID,
		active,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLBMemberNotFound
	}

	s.updateCachedMemberState(memberUUID, active)
	return nil
}

func (s *LBService) IsOwner(ctx context.Context, groupID string, userID string) (bool, error) {
	groupUUID, err := uuid.Parse(strings.TrimSpace(groupID))
	if err != nil {
		return false, ErrInvalidLBInput
	}
	userUUID, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return false, ErrInvalidUserID
	}

	var ownerID *uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT owner_id FROM lb_groups WHERE id = $1`, groupUUID).Scan(&ownerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrLBGroupNotFound
		}
		return false, err
	}

	return ownerID != nil && *ownerID == userUUID, nil
}

func (s *LBService) getSelectorCache(ctx context.Context, groupID uuid.UUID) (*lbSelectorCache, error) {
	key := groupID.String()
	if current, ok := s.selectorCache.Load(key); ok {
		if cache, valid := current.(*lbSelectorCache); valid {
			return cache, nil
		}
	}

	cache, err := s.loadSelectorCache(ctx, groupID)
	if err != nil {
		return nil, err
	}
	s.selectorCache.Store(key, cache)
	return cache, nil
}

func (s *LBService) loadSelectorCache(ctx context.Context, groupID uuid.UUID) (*lbSelectorCache, error) {
	group, err := s.findGroupByID(ctx, groupID)
	if err != nil {
		return nil, err
	}

	members, err := s.ListMembers(ctx, groupID.String())
	if err != nil {
		return nil, err
	}

	return &lbSelectorCache{
		Group:   group,
		Members: members,
		Select:  NewSelector(group.Strategy, members),
	}, nil
}

func (s *LBService) findGroupByID(ctx context.Context, groupID uuid.UUID) (*model.LBGroup, error) {
	item, err := scanLBGroup(s.pool.QueryRow(
		ctx,
		`SELECT id, name, owner_id, strategy, health_check_interval, created_at
		   FROM lb_groups
		  WHERE id = $1`,
		groupID,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrLBGroupNotFound
		}
		return nil, err
	}
	return item, nil
}

func (s *LBService) findMemberByID(ctx context.Context, groupID uuid.UUID, memberID uuid.UUID) (*model.LBGroupMember, error) {
	item, err := scanLBGroupMember(s.pool.QueryRow(
		ctx,
		`SELECT id, group_id, node_id, weight, is_active, created_at
		   FROM lb_group_members
		  WHERE id = $1
		    AND group_id = $2`,
		memberID,
		groupID,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrLBMemberNotFound
		}
		return nil, err
	}
	return item, nil
}

func (s *LBService) healthCheckLoop() {
	ticker := time.NewTicker(lbHealthTickPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.runHealthChecks()
		}
	}
}

func (s *LBService) runHealthChecks() {
	if s.pool == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := s.pool.Query(
		ctx,
		`SELECT id, name, owner_id, strategy, health_check_interval, created_at FROM lb_groups`,
	)
	if err != nil {
		s.logger.Warn("query lb groups for health check failed", zap.Error(err))
		return
	}
	defer rows.Close()

	now := time.Now().UTC()
	for rows.Next() {
		group, scanErr := scanLBGroup(rows)
		if scanErr != nil {
			s.logger.Warn("scan lb group failed", zap.Error(scanErr))
			continue
		}

		interval := time.Duration(normalizeHealthInterval(group.HealthCheckInterval)) * time.Second
		lastAny, loaded := s.lastHealthRun.Load(group.ID.String())
		if loaded {
			if lastRun, ok := lastAny.(time.Time); ok && now.Sub(lastRun) < interval {
				continue
			}
		}
		s.lastHealthRun.Store(group.ID.String(), now)

		go s.checkGroupHealth(*group)
	}
}

func (s *LBService) checkGroupHealth(group model.LBGroup) {
	if s.pool == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rows, err := s.pool.Query(
		ctx,
		`SELECT m.id, m.group_id, m.node_id, m.weight, m.is_active, m.created_at, COALESCE(n.status, '')
		   FROM lb_group_members m
		   LEFT JOIN node_agents n ON n.id = m.node_id
		  WHERE m.group_id = $1`,
		group.ID,
	)
	if err != nil {
		s.logger.Warn("query lb members for health check failed",
			zap.String("group_id", group.ID.String()),
			zap.Error(err),
		)
		return
	}
	defer rows.Close()

	for rows.Next() {
		member := &model.LBGroupMember{}
		var nodeStatus string
		if err := rows.Scan(
			&member.ID,
			&member.GroupID,
			&member.NodeID,
			&member.Weight,
			&member.IsActive,
			&member.CreatedAt,
			&nodeStatus,
		); err != nil {
			s.logger.Warn("scan lb member health row failed", zap.Error(err))
			continue
		}

		shouldActive := false
		reason := "node offline"
		if strings.EqualFold(strings.TrimSpace(nodeStatus), "online") {
			shouldActive = true
			reason = ""

			if s.hub != nil {
				pingCtx, pingCancel := context.WithTimeout(context.Background(), 3*time.Second)
				pingErr := s.hub.PingAgent(pingCtx, member.NodeID.String(), 3*time.Second)
				pingCancel()
				if pingErr != nil {
					shouldActive = false
					reason = pingErr.Error()
				}
			}
		}

		if member.IsActive == shouldActive {
			continue
		}

		if _, err := s.pool.Exec(
			ctx,
			`UPDATE lb_group_members SET is_active = $2 WHERE id = $1`,
			member.ID,
			shouldActive,
		); err != nil {
			s.logger.Warn("update lb member active failed",
				zap.String("member_id", member.ID.String()),
				zap.Error(err),
			)
			continue
		}

		s.updateCachedMemberState(member.ID, shouldActive)
		s.emitHealthAlert(&group, member, shouldActive, reason)
	}
}

func (s *LBService) emitHealthAlert(group *model.LBGroup, member *model.LBGroupMember, active bool, reason string) {
	if s.sseHub == nil || group == nil || member == nil {
		return
	}

	payload := map[string]interface{}{
		"group_id":   group.ID.String(),
		"group_name": group.Name,
		"member_id":  member.ID.String(),
		"node_id":    member.NodeID.String(),
		"is_active":  active,
		"reason":     strings.TrimSpace(reason),
		"ts":         time.Now().UTC().Format(time.RFC3339Nano),
	}

	event := sse.NewEvent(sse.EventSystemAlert, payload)
	s.sseHub.SendToRole(string(model.UserRoleAdmin), event)
	if group.OwnerID != nil {
		s.sseHub.SendToUser(group.OwnerID.String(), event)
	}
}

func (s *LBService) updateCachedMemberState(memberID uuid.UUID, active bool) {
	s.selectorCache.Range(func(_, value interface{}) bool {
		cache, ok := value.(*lbSelectorCache)
		if !ok || cache == nil {
			return true
		}
		for _, member := range cache.Members {
			if member == nil || member.ID != memberID {
				continue
			}
			member.IsActive = active
		}
		return true
	})
}

func activeMembers(members []*model.LBGroupMember) []*model.LBGroupMember {
	if len(members) == 0 {
		return nil
	}

	active := make([]*model.LBGroupMember, 0, len(members))
	for _, member := range members {
		if member == nil || !member.IsActive {
			continue
		}
		active = append(active, member)
	}
	return active
}

func normalizeLBStrategy(strategy string) string {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "round_robin":
		return "round_robin"
	case "least_conn":
		return "least_conn"
	case "random":
		return "random"
	case "ip_hash":
		return "ip_hash"
	default:
		return "round_robin"
	}
}

func normalizeHealthInterval(interval int) int {
	if interval <= 0 {
		return 30
	}
	if interval < 5 {
		return 5
	}
	return interval
}

func normalizeLBPagination(page, pageSize int) (int, int) {
	if page <= 0 {
		page = lbListDefaultPage
	}
	if pageSize <= 0 {
		pageSize = lbListDefaultSize
	}
	if pageSize > lbListMaxPageSize {
		pageSize = lbListMaxPageSize
	}
	return page, pageSize
}

func scanLBGroup(src rowScanner) (*model.LBGroup, error) {
	item := &model.LBGroup{}
	if err := src.Scan(
		&item.ID,
		&item.Name,
		&item.OwnerID,
		&item.Strategy,
		&item.HealthCheckInterval,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	return item, nil
}

func scanLBGroupMember(src rowScanner) (*model.LBGroupMember, error) {
	item := &model.LBGroupMember{}
	if err := src.Scan(
		&item.ID,
		&item.GroupID,
		&item.NodeID,
		&item.Weight,
		&item.IsActive,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	return item, nil
}

func parseIPHashInput(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	if host, _, found := strings.Cut(trimmed, ":"); found {
		return host
	}
	return trimmed
}
