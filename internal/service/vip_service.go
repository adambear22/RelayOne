package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/event"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/sse"
)

const (
	defaultSystemTrafficQuota int64 = 10737418240
	defaultSystemMaxRules     int   = 5
)

var (
	ErrVIPLevelNotFound     = errors.New("vip level not found")
	ErrInvalidVIPLevelInput = errors.New("invalid vip level input")
)

const vipLevelColumns = `
	level,
	name,
	traffic_quota,
	max_rules,
	bandwidth_limit,
	max_ingress_nodes,
	max_egress_nodes,
	accessible_node_level,
	traffic_ratio,
	custom_features,
	created_at
`

type CreateVIPLevelRequest struct {
	Level               int                    `json:"level"`
	Name                string                 `json:"name"`
	TrafficQuota        int64                  `json:"traffic_quota"`
	MaxRules            int                    `json:"max_rules"`
	BandwidthLimit      int64                  `json:"bandwidth_limit"`
	MaxIngressNodes     int                    `json:"max_ingress_nodes"`
	MaxEgressNodes      int                    `json:"max_egress_nodes"`
	AccessibleNodeLevel int                    `json:"accessible_node_level"`
	TrafficRatio        float64                `json:"traffic_ratio"`
	CustomFeatures      map[string]interface{} `json:"custom_features"`
}

type UpdateVIPLevelRequest struct {
	Name                *string                 `json:"name"`
	TrafficQuota        *int64                  `json:"traffic_quota"`
	MaxRules            *int                    `json:"max_rules"`
	BandwidthLimit      *int64                  `json:"bandwidth_limit"`
	MaxIngressNodes     *int                    `json:"max_ingress_nodes"`
	MaxEgressNodes      *int                    `json:"max_egress_nodes"`
	AccessibleNodeLevel *int                    `json:"accessible_node_level"`
	TrafficRatio        *float64                `json:"traffic_ratio"`
	CustomFeatures      *map[string]interface{} `json:"custom_features"`
}

type UserVIPEntitlement struct {
	UserID         string          `json:"user_id"`
	VIPLevel       int             `json:"vip_level"`
	VIPExpiresAt   *time.Time      `json:"vip_expires_at,omitempty"`
	TrafficQuota   int64           `json:"traffic_quota"`
	MaxRules       int             `json:"max_rules"`
	BandwidthLimit int64           `json:"bandwidth_limit"`
	LevelInfo      *model.VIPLevel `json:"level_info,omitempty"`
}

type VIPService struct {
	userRepo  repository.UserRepository
	auditRepo repository.AuditRepository
	pool      *pgxpool.Pool
	ruleSvc   *RuleService
	eventBus  *event.Bus
	sseHub    *sse.SSEHub
	logger    *zap.Logger
}

type vipUpgradeResult struct {
	UserID            uuid.UUID
	OldVIPLevel       int
	NewVIPLevel       int
	OldVIPExpiresAt   *time.Time
	NewVIPExpiresAt   *time.Time
	OldTrafficQuota   int64
	NewTrafficQuota   int64
	OldMaxRules       int
	NewMaxRules       int
	OldBandwidthLimit int64
}

type systemDefaults struct {
	TrafficQuota int64
	MaxRules     int
}

type rowScanner interface {
	Scan(dest ...any) error
}

func NewVIPService(
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	pool *pgxpool.Pool,
	ruleSvc *RuleService,
	eventBus *event.Bus,
	sseHub *sse.SSEHub,
	logger *zap.Logger,
) *VIPService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &VIPService{
		userRepo:  userRepo,
		auditRepo: auditRepo,
		pool:      pool,
		ruleSvc:   ruleSvc,
		eventBus:  eventBus,
		sseHub:    sseHub,
		logger:    logger,
	}
}

func (s *VIPService) GetLevel(ctx context.Context, level int) (*model.VIPLevel, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}
	if level < 0 {
		return nil, ErrInvalidVIPLevelInput
	}

	query := `SELECT ` + vipLevelColumns + ` FROM vip_levels WHERE level = $1`
	item, err := scanVIPLevel(s.pool.QueryRow(ctx, query, level))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVIPLevelNotFound
		}
		return nil, err
	}

	return item, nil
}

func (s *VIPService) ListLevels(ctx context.Context) ([]*model.VIPLevel, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	rows, err := s.pool.Query(ctx, `SELECT `+vipLevelColumns+` FROM vip_levels ORDER BY level ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	levels := make([]*model.VIPLevel, 0, 16)
	for rows.Next() {
		item, scanErr := scanVIPLevel(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		levels = append(levels, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return levels, nil
}

func (s *VIPService) CreateLevel(ctx context.Context, req CreateVIPLevelRequest) (*model.VIPLevel, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}
	if req.Level < 0 || strings.TrimSpace(req.Name) == "" {
		return nil, ErrInvalidVIPLevelInput
	}

	ratio := req.TrafficRatio
	if ratio <= 0 {
		ratio = 1.0
	}

	customFeatures, err := json.Marshal(req.CustomFeatures)
	if err != nil {
		return nil, err
	}

	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO vip_levels (
			level, name, traffic_quota, max_rules, bandwidth_limit,
			max_ingress_nodes, max_egress_nodes, accessible_node_level,
			traffic_ratio, custom_features, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		req.Level,
		strings.TrimSpace(req.Name),
		req.TrafficQuota,
		req.MaxRules,
		req.BandwidthLimit,
		req.MaxIngressNodes,
		req.MaxEgressNodes,
		req.AccessibleNodeLevel,
		ratio,
		customFeatures,
		time.Now().UTC(),
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrInvalidVIPLevelInput
		}
		return nil, err
	}

	return s.GetLevel(ctx, req.Level)
}

func (s *VIPService) UpdateLevel(ctx context.Context, level int, req UpdateVIPLevelRequest) (*model.VIPLevel, error) {
	if level < 0 {
		return nil, ErrInvalidVIPLevelInput
	}

	current, err := s.GetLevel(ctx, level)
	if err != nil {
		return nil, err
	}

	next := *current
	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			return nil, ErrInvalidVIPLevelInput
		}
		next.Name = trimmed
	}
	if req.TrafficQuota != nil {
		next.TrafficQuota = *req.TrafficQuota
	}
	if req.MaxRules != nil {
		next.MaxRules = *req.MaxRules
	}
	if req.BandwidthLimit != nil {
		next.BandwidthLimit = *req.BandwidthLimit
	}
	if req.MaxIngressNodes != nil {
		next.MaxIngressNodes = *req.MaxIngressNodes
	}
	if req.MaxEgressNodes != nil {
		next.MaxEgressNodes = *req.MaxEgressNodes
	}
	if req.AccessibleNodeLevel != nil {
		next.AccessibleNodeLevel = *req.AccessibleNodeLevel
	}
	if req.TrafficRatio != nil {
		if *req.TrafficRatio <= 0 {
			return nil, ErrInvalidVIPLevelInput
		}
		next.TrafficRatio = *req.TrafficRatio
	}
	if req.CustomFeatures != nil {
		next.CustomFeatures = cloneAnyMap(*req.CustomFeatures)
	}

	customFeatures, err := json.Marshal(next.CustomFeatures)
	if err != nil {
		return nil, err
	}

	tag, err := s.pool.Exec(
		ctx,
		`UPDATE vip_levels
		 SET name = $2,
		     traffic_quota = $3,
		     max_rules = $4,
		     bandwidth_limit = $5,
		     max_ingress_nodes = $6,
		     max_egress_nodes = $7,
		     accessible_node_level = $8,
		     traffic_ratio = $9,
		     custom_features = $10
		 WHERE level = $1`,
		level,
		next.Name,
		next.TrafficQuota,
		next.MaxRules,
		next.BandwidthLimit,
		next.MaxIngressNodes,
		next.MaxEgressNodes,
		next.AccessibleNodeLevel,
		next.TrafficRatio,
		customFeatures,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrVIPLevelNotFound
	}

	return s.GetLevel(ctx, level)
}

func (s *VIPService) DeleteLevel(ctx context.Context, level int) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}
	if level < 0 {
		return ErrInvalidVIPLevelInput
	}

	tag, err := s.pool.Exec(ctx, `DELETE FROM vip_levels WHERE level = $1`, level)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVIPLevelNotFound
	}
	return nil
}

func (s *VIPService) UpgradeUser(ctx context.Context, operatorID, userID string, level int, validDays int) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return ErrInvalidUserID
	}
	if level < 0 || validDays < 0 {
		return ErrInvalidVIPLevelInput
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	result, err := s.upgradeUserTx(ctx, tx, uid, level, validDays)
	if err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	s.writeUpgradeAudit(ctx, operatorID, result)

	return nil
}

func (s *VIPService) CheckExpiry(ctx context.Context) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	defaults, err := s.loadSystemDefaults(ctx)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	rows, err := s.pool.Query(
		ctx,
		`SELECT id
		   FROM users
		  WHERE vip_level > 0
		    AND vip_expires_at IS NOT NULL
		    AND vip_expires_at < $1`,
		now,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	var firstErr error
	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return err
		}

		if err := s.expireSingleUser(ctx, userID, defaults, now); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.logger.Warn("handle vip expiry failed",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	return firstErr
}

func (s *VIPService) GetUserEntitlement(ctx context.Context, userID string) (*UserVIPEntitlement, error) {
	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	var levelInfo *model.VIPLevel
	if user.VIPLevel >= 0 {
		info, levelErr := s.GetLevel(ctx, user.VIPLevel)
		if levelErr == nil {
			levelInfo = info
		}
	}

	return &UserVIPEntitlement{
		UserID:         user.ID.String(),
		VIPLevel:       user.VIPLevel,
		VIPExpiresAt:   user.VIPExpiresAt,
		TrafficQuota:   user.TrafficQuota,
		MaxRules:       user.MaxRules,
		BandwidthLimit: user.BandwidthLimit,
		LevelInfo:      levelInfo,
	}, nil
}

func (s *VIPService) upgradeUserTx(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	level int,
	validDays int,
) (*vipUpgradeResult, error) {
	if tx == nil {
		return nil, errors.New("tx is nil")
	}
	if level < 0 || validDays < 0 {
		return nil, ErrInvalidVIPLevelInput
	}

	var oldLevel int
	var oldExpiresAt *time.Time
	var oldTrafficQuota int64
	var oldMaxRules int
	var oldBandwidthLimit int64
	err := tx.QueryRow(
		ctx,
		`SELECT vip_level, vip_expires_at, traffic_quota, max_rules, bandwidth_limit
		   FROM users
		  WHERE id = $1
		  FOR UPDATE`,
		userID,
	).Scan(
		&oldLevel,
		&oldExpiresAt,
		&oldTrafficQuota,
		&oldMaxRules,
		&oldBandwidthLimit,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	var newTrafficQuota int64
	var newMaxRules int
	err = tx.QueryRow(
		ctx,
		`SELECT traffic_quota, max_rules
		   FROM vip_levels
		  WHERE level = $1`,
		level,
	).Scan(&newTrafficQuota, &newMaxRules)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVIPLevelNotFound
		}
		return nil, err
	}

	now := time.Now().UTC()
	baseTime := now
	if oldExpiresAt != nil && oldExpiresAt.After(now) {
		baseTime = oldExpiresAt.UTC()
	}

	newExpiresAtValue := baseTime.Add(time.Duration(validDays) * 24 * time.Hour)
	newExpiresAt := &newExpiresAtValue

	tag, err := tx.Exec(
		ctx,
		`UPDATE users
		    SET vip_level = $2,
		        vip_expires_at = $3,
		        traffic_quota = $4,
		        max_rules = $5,
		        updated_at = NOW()
		  WHERE id = $1`,
		userID,
		level,
		newExpiresAt,
		newTrafficQuota,
		newMaxRules,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrUserNotFound
	}

	return &vipUpgradeResult{
		UserID:            userID,
		OldVIPLevel:       oldLevel,
		NewVIPLevel:       level,
		OldVIPExpiresAt:   cloneTimePtr(oldExpiresAt),
		NewVIPExpiresAt:   cloneTimePtr(newExpiresAt),
		OldTrafficQuota:   oldTrafficQuota,
		NewTrafficQuota:   newTrafficQuota,
		OldMaxRules:       oldMaxRules,
		NewMaxRules:       newMaxRules,
		OldBandwidthLimit: oldBandwidthLimit,
	}, nil
}

func (s *VIPService) expireSingleUser(
	ctx context.Context,
	userID uuid.UUID,
	defaults systemDefaults,
	now time.Time,
) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var oldLevel int
	var oldExpiresAt *time.Time
	err = tx.QueryRow(
		ctx,
		`SELECT vip_level, vip_expires_at
		   FROM users
		  WHERE id = $1
		  FOR UPDATE`,
		userID,
	).Scan(&oldLevel, &oldExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}

	if oldLevel <= 0 || oldExpiresAt == nil || !oldExpiresAt.Before(now) {
		return nil
	}

	if _, err := tx.Exec(
		ctx,
		`UPDATE users
		    SET vip_level = 0,
		        vip_expires_at = NULL,
		        traffic_quota = $2,
		        max_rules = $3,
		        updated_at = NOW()
		  WHERE id = $1`,
		userID,
		defaults.TrafficQuota,
		defaults.MaxRules,
	); err != nil {
		return err
	}

	runningRuleIDs := make([]uuid.UUID, 0, 16)
	rows, err := tx.Query(
		ctx,
		`SELECT id
		   FROM forwarding_rules
		  WHERE owner_id = $1
		    AND status = 'running'
		  ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ruleID uuid.UUID
		if scanErr := rows.Scan(&ruleID); scanErr != nil {
			rows.Close()
			return scanErr
		}
		runningRuleIDs = append(runningRuleIDs, ruleID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	rulesToPause := runningRuleIDs
	if defaults.MaxRules > 0 && len(runningRuleIDs) > defaults.MaxRules {
		rulesToPause = runningRuleIDs[defaults.MaxRules:]
	} else if defaults.MaxRules > 0 {
		rulesToPause = nil
	}

	for _, ruleID := range rulesToPause {
		s.pauseExpiredRule(ctx, userID, ruleID)
	}

	if s.eventBus != nil {
		s.eventBus.Publish(event.EventUserVIPExpired, event.VIPExpiredPayload{
			UserID: userID.String(),
		})
	}

	if s.sseHub != nil {
		s.sseHub.SendToUser(userID.String(), sse.NewEvent(sse.EventTrafficUpdate, map[string]interface{}{
			"user_id": userID.String(),
			"status":  "vip_expired",
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		}))
	}

	if s.auditRepo != nil {
		s.writeVIPExpiryAudit(ctx, userID, oldLevel, oldExpiresAt, defaults, rulesToPause)
	}

	return nil
}

func (s *VIPService) pauseExpiredRule(ctx context.Context, userID uuid.UUID, ruleID uuid.UUID) {
	if s.ruleSvc != nil {
		if err := s.ruleSvc.Stop(ctx, ruleID.String(), userID.String()); err == nil {
			return
		} else {
			s.logger.Warn("pause expired vip rule via rule service failed, fallback to db",
				zap.String("user_id", userID.String()),
				zap.String("rule_id", ruleID.String()),
				zap.Error(err),
			)
		}
	}

	if _, err := s.pool.Exec(
		ctx,
		`UPDATE forwarding_rules
		    SET status = 'paused',
		        sync_status = 'sync_failed',
		        updated_at = NOW()
		  WHERE id = $1`,
		ruleID,
	); err != nil {
		s.logger.Warn("fallback pause rule failed",
			zap.String("rule_id", ruleID.String()),
			zap.Error(err),
		)
	}
}

func (s *VIPService) loadSystemDefaults(ctx context.Context) (systemDefaults, error) {
	defaults := systemDefaults{
		TrafficQuota: defaultSystemTrafficQuota,
		MaxRules:     defaultSystemMaxRules,
	}

	if s.pool == nil {
		return defaults, nil
	}

	err := s.pool.QueryRow(
		ctx,
		`SELECT default_traffic_quota, default_max_rules
		   FROM system_configs
		  WHERE id = 1`,
	).Scan(&defaults.TrafficQuota, &defaults.MaxRules)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return defaults, nil
		}
		return defaults, err
	}

	return defaults, nil
}

func (s *VIPService) writeUpgradeAudit(ctx context.Context, operatorID string, result *vipUpgradeResult) {
	if s.auditRepo == nil || result == nil {
		return
	}

	var actorID *uuid.UUID
	if strings.TrimSpace(operatorID) != "" {
		if parsed, err := uuid.Parse(strings.TrimSpace(operatorID)); err == nil {
			actorID = &parsed
		}
	}

	userID := result.UserID.String()
	_ = s.auditRepo.Create(ctx, &model.AuditLog{
		UserID:       actorID,
		Action:       "user.vip_upgrade",
		ResourceType: strPtr("user"),
		ResourceID:   strPtr(userID),
		OldValue: map[string]interface{}{
			"vip_level":      result.OldVIPLevel,
			"vip_expires_at": formatTimePtr(result.OldVIPExpiresAt),
			"traffic_quota":  result.OldTrafficQuota,
			"max_rules":      result.OldMaxRules,
		},
		NewValue: map[string]interface{}{
			"vip_level":      result.NewVIPLevel,
			"vip_expires_at": formatTimePtr(result.NewVIPExpiresAt),
			"traffic_quota":  result.NewTrafficQuota,
			"max_rules":      result.NewMaxRules,
		},
		CreatedAt: time.Now().UTC(),
	})
}

func (s *VIPService) writeVIPExpiryAudit(
	ctx context.Context,
	userID uuid.UUID,
	oldLevel int,
	oldExpiresAt *time.Time,
	defaults systemDefaults,
	pausedRules []uuid.UUID,
) {
	if s.auditRepo == nil {
		return
	}

	paused := make([]string, 0, len(pausedRules))
	for _, ruleID := range pausedRules {
		paused = append(paused, ruleID.String())
	}

	id := userID.String()
	_ = s.auditRepo.Create(ctx, &model.AuditLog{
		UserID:       &userID,
		Action:       "user.vip.expired",
		ResourceType: strPtr("user"),
		ResourceID:   strPtr(id),
		OldValue: map[string]interface{}{
			"vip_level":      oldLevel,
			"vip_expires_at": formatTimePtr(oldExpiresAt),
		},
		NewValue: map[string]interface{}{
			"vip_level":      0,
			"vip_expires_at": nil,
			"traffic_quota":  defaults.TrafficQuota,
			"max_rules":      defaults.MaxRules,
			"paused_rules":   paused,
		},
		CreatedAt: time.Now().UTC(),
	})
}

func scanVIPLevel(src rowScanner) (*model.VIPLevel, error) {
	item := &model.VIPLevel{}
	var customFeaturesRaw []byte
	err := src.Scan(
		&item.Level,
		&item.Name,
		&item.TrafficQuota,
		&item.MaxRules,
		&item.BandwidthLimit,
		&item.MaxIngressNodes,
		&item.MaxEgressNodes,
		&item.AccessibleNodeLevel,
		&item.TrafficRatio,
		&customFeaturesRaw,
		&item.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if len(customFeaturesRaw) > 0 {
		if err := json.Unmarshal(customFeaturesRaw, &item.CustomFeatures); err != nil {
			return nil, err
		}
	}

	return item, nil
}

func cloneAnyMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneTimePtr(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	cloned := v.UTC()
	return &cloned
}

func formatTimePtr(v *time.Time) interface{} {
	if v == nil {
		return nil
	}
	return v.UTC().Format(time.RFC3339)
}
