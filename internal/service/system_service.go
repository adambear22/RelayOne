package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/api/middleware"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/sse"
)

const (
	systemConfigDefaultCacheTTL   = 60 * time.Second
	systemConfigDefaultTrafficCap = int64(10737418240)
	systemConfigDefaultMaxRules   = 5
)

var (
	ErrInvalidSystemConfigInput = errors.New("invalid system config input")
)

type UpdateSystemConfigRequest struct {
	SiteName            *string                 `json:"site_name"`
	SupportEmail        *string                 `json:"support_email"`
	MaintenanceMode     *bool                   `json:"maintenance_mode"`
	RegistrationEnabled *bool                   `json:"registration_enabled"`
	DefaultTrafficQuota *int64                  `json:"default_traffic_quota"`
	DefaultMaxRules     *int                    `json:"default_max_rules"`
	TelegramConfig      *model.TelegramConfig   `json:"telegram_config"`
	ExternalAPIKeys     *[]model.ExternalAPIKey `json:"external_api_keys"`
}

type SystemService struct {
	pool      *pgxpool.Pool
	auditRepo repository.AuditRepository
	sseHub    *sse.SSEHub
	logger    *zap.Logger

	cacheTTL time.Duration
	cacheMu  sync.RWMutex
	cache    *model.SystemConfig
	cacheExp time.Time
}

func NewSystemService(
	pool *pgxpool.Pool,
	auditRepo repository.AuditRepository,
	sseHub *sse.SSEHub,
	logger *zap.Logger,
) *SystemService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &SystemService{
		pool:      pool,
		auditRepo: auditRepo,
		sseHub:    sseHub,
		logger:    logger,
		cacheTTL:  systemConfigDefaultCacheTTL,
	}
}

func (s *SystemService) GetConfig(ctx context.Context) (*model.SystemConfig, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	if cfg := s.getCachedConfig(); cfg != nil {
		return cfg, nil
	}

	cfg, err := s.loadSystemConfig(ctx)
	if err != nil {
		return nil, err
	}

	s.setCachedConfig(cfg)
	middleware.SetSystemConfigCache(cfg)
	return cloneSystemConfig(cfg), nil
}

func (s *SystemService) UpdateConfig(ctx context.Context, operatorID string, req UpdateSystemConfigRequest) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	current, err := s.loadSystemConfig(ctx)
	if err != nil {
		return err
	}

	next := cloneSystemConfig(current)
	if err := applySystemConfigUpdate(next, req); err != nil {
		return err
	}

	telegramRaw, err := json.Marshal(next.TelegramConfig)
	if err != nil {
		return err
	}
	externalAPIKeysRaw, err := json.Marshal(next.ExternalAPIKeys)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO system_configs (
			id, site_name, support_email, maintenance_mode, registration_enabled,
			default_traffic_quota, default_max_rules, telegram_config, external_api_keys, updated_at
		)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, NOW())
		ON CONFLICT (id)
		DO UPDATE SET
			site_name = EXCLUDED.site_name,
			support_email = EXCLUDED.support_email,
			maintenance_mode = EXCLUDED.maintenance_mode,
			registration_enabled = EXCLUDED.registration_enabled,
			default_traffic_quota = EXCLUDED.default_traffic_quota,
			default_max_rules = EXCLUDED.default_max_rules,
			telegram_config = EXCLUDED.telegram_config,
			external_api_keys = EXCLUDED.external_api_keys,
			updated_at = NOW()`,
		next.SiteName,
		next.SupportEmail,
		next.MaintenanceMode,
		next.RegistrationEnabled,
		next.DefaultTrafficQuota,
		next.DefaultMaxRules,
		string(telegramRaw),
		string(externalAPIKeysRaw),
	)
	if err != nil {
		return err
	}

	next.UpdatedAt = time.Now().UTC()

	s.invalidateCache()
	s.setCachedConfig(next)
	middleware.SetSystemConfigCache(next)

	s.writeUpdateAudit(ctx, operatorID, current, next)
	if s.sseHub != nil {
		s.sseHub.Broadcast(sse.NewEvent(sse.EventSystemAlert, map[string]interface{}{
			"type":             "system.config.updated",
			"maintenance_mode": next.MaintenanceMode,
			"updated_at":       next.UpdatedAt.Format(time.RFC3339Nano),
		}))
	}

	return nil
}

func (s *SystemService) getCachedConfig() *model.SystemConfig {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()

	if s.cache == nil || time.Now().UTC().After(s.cacheExp) {
		return nil
	}
	return cloneSystemConfig(s.cache)
}

func (s *SystemService) setCachedConfig(cfg *model.SystemConfig) {
	if cfg == nil {
		return
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cache = cloneSystemConfig(cfg)
	s.cacheExp = time.Now().UTC().Add(s.cacheTTL)
}

func (s *SystemService) invalidateCache() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cache = nil
	s.cacheExp = time.Time{}
}

func (s *SystemService) loadSystemConfig(ctx context.Context) (*model.SystemConfig, error) {
	if err := s.ensureSystemConfigRow(ctx); err != nil {
		return nil, err
	}

	var cfg model.SystemConfig
	var telegramRaw []byte
	var externalAPIKeysRaw []byte

	err := s.pool.QueryRow(
		ctx,
		`SELECT
			id,
			site_name,
			support_email,
			COALESCE(maintenance_mode, FALSE),
			COALESCE(registration_enabled, TRUE),
			COALESCE(default_traffic_quota, $1),
			COALESCE(default_max_rules, $2),
			COALESCE(telegram_config, '{}'::jsonb),
			COALESCE(external_api_keys, '[]'::jsonb),
			updated_at
		FROM system_configs
		WHERE id = 1`,
		systemConfigDefaultTrafficCap,
		systemConfigDefaultMaxRules,
	).Scan(
		&cfg.ID,
		&cfg.SiteName,
		&cfg.SupportEmail,
		&cfg.MaintenanceMode,
		&cfg.RegistrationEnabled,
		&cfg.DefaultTrafficQuota,
		&cfg.DefaultMaxRules,
		&telegramRaw,
		&externalAPIKeysRaw,
		&cfg.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidSystemConfigInput
		}
		return nil, err
	}

	cfg.TelegramConfig = model.TelegramConfig{}
	if len(telegramRaw) > 0 {
		_ = json.Unmarshal(telegramRaw, &cfg.TelegramConfig)
	}
	cfg.ExternalAPIKeys = normalizeExternalAPIKeys(nil)
	if len(externalAPIKeysRaw) > 0 {
		var keys []model.ExternalAPIKey
		if err := json.Unmarshal(externalAPIKeysRaw, &keys); err == nil {
			cfg.ExternalAPIKeys = normalizeExternalAPIKeys(keys)
		}
	}

	return &cfg, nil
}

func (s *SystemService) ensureSystemConfigRow(ctx context.Context) error {
	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO system_configs (
			id, maintenance_mode, registration_enabled, default_traffic_quota, default_max_rules, telegram_config, external_api_keys, updated_at
		)
		VALUES (1, FALSE, TRUE, $1, $2, '{}'::jsonb, '[]'::jsonb, NOW())
		ON CONFLICT (id) DO NOTHING`,
		systemConfigDefaultTrafficCap,
		systemConfigDefaultMaxRules,
	)
	return err
}

func applySystemConfigUpdate(cfg *model.SystemConfig, req UpdateSystemConfigRequest) error {
	if cfg == nil {
		return ErrInvalidSystemConfigInput
	}

	if req.SiteName != nil {
		cfg.SiteName = normalizedNullableString(*req.SiteName)
	}
	if req.SupportEmail != nil {
		cfg.SupportEmail = normalizedNullableString(*req.SupportEmail)
	}
	if req.MaintenanceMode != nil {
		cfg.MaintenanceMode = *req.MaintenanceMode
	}
	if req.RegistrationEnabled != nil {
		cfg.RegistrationEnabled = *req.RegistrationEnabled
	}
	if req.DefaultTrafficQuota != nil {
		if *req.DefaultTrafficQuota < 0 {
			return ErrInvalidSystemConfigInput
		}
		cfg.DefaultTrafficQuota = *req.DefaultTrafficQuota
	}
	if req.DefaultMaxRules != nil {
		if *req.DefaultMaxRules <= 0 {
			return ErrInvalidSystemConfigInput
		}
		cfg.DefaultMaxRules = *req.DefaultMaxRules
	}
	if req.TelegramConfig != nil {
		cfg.TelegramConfig = *req.TelegramConfig
	}
	if req.ExternalAPIKeys != nil {
		cfg.ExternalAPIKeys = normalizeExternalAPIKeys(*req.ExternalAPIKeys)
	}

	return nil
}

func normalizedNullableString(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func cloneSystemConfig(cfg *model.SystemConfig) *model.SystemConfig {
	if cfg == nil {
		return nil
	}

	cloned := *cfg
	cloned.SiteName = cloneStringPointer(cfg.SiteName)
	cloned.SupportEmail = cloneStringPointer(cfg.SupportEmail)
	cloned.ExternalAPIKeys = cloneExternalAPIKeys(cfg.ExternalAPIKeys)
	return &cloned
}

func cloneStringPointer(v *string) *string {
	if v == nil {
		return nil
	}
	copyValue := *v
	return &copyValue
}

func normalizeExternalAPIKeys(keys []model.ExternalAPIKey) []model.ExternalAPIKey {
	if len(keys) == 0 {
		return nil
	}

	normalized := make([]model.ExternalAPIKey, 0, len(keys))
	for _, item := range keys {
		keyValue := strings.TrimSpace(item.Key)
		if keyValue == "" {
			continue
		}

		entry := model.ExternalAPIKey{
			Name: strings.TrimSpace(item.Name),
			Key:  keyValue,
		}
		if entry.Name == "" {
			entry.Name = "default"
		}

		scopes := make([]string, 0, len(item.Scopes))
		seen := make(map[string]struct{}, len(item.Scopes))
		for _, rawScope := range item.Scopes {
			scope := strings.TrimSpace(rawScope)
			if scope == "" {
				continue
			}
			lowered := strings.ToLower(scope)
			if _, exists := seen[lowered]; exists {
				continue
			}
			seen[lowered] = struct{}{}
			scopes = append(scopes, scope)
		}
		entry.Scopes = scopes

		normalized = append(normalized, entry)
	}

	if len(normalized) == 0 {
		return nil
	}

	return normalized
}

func cloneExternalAPIKeys(keys []model.ExternalAPIKey) []model.ExternalAPIKey {
	if len(keys) == 0 {
		return nil
	}

	out := make([]model.ExternalAPIKey, 0, len(keys))
	for _, key := range keys {
		copyKey := model.ExternalAPIKey{
			Name: strings.TrimSpace(key.Name),
			Key:  strings.TrimSpace(key.Key),
		}
		if len(key.Scopes) > 0 {
			copyKey.Scopes = make([]string, 0, len(key.Scopes))
			for _, scope := range key.Scopes {
				trimmed := strings.TrimSpace(scope)
				if trimmed != "" {
					copyKey.Scopes = append(copyKey.Scopes, trimmed)
				}
			}
		}
		out = append(out, copyKey)
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func externalAPIKeysAuditView(keys []model.ExternalAPIKey) []map[string]interface{} {
	if len(keys) == 0 {
		return nil
	}

	view := make([]map[string]interface{}, 0, len(keys))
	for _, key := range keys {
		item := map[string]interface{}{
			"name":   strings.TrimSpace(key.Name),
			"scopes": append([]string(nil), key.Scopes...),
		}
		view = append(view, item)
	}

	return view
}

func (s *SystemService) writeUpdateAudit(
	ctx context.Context,
	operatorID string,
	oldCfg, newCfg *model.SystemConfig,
) {
	if s.auditRepo == nil || oldCfg == nil || newCfg == nil {
		return
	}

	oldValue := make(map[string]interface{})
	newValue := make(map[string]interface{})

	if !reflect.DeepEqual(oldCfg.SiteName, newCfg.SiteName) {
		oldValue["site_name"] = oldCfg.SiteName
		newValue["site_name"] = newCfg.SiteName
	}
	if !reflect.DeepEqual(oldCfg.SupportEmail, newCfg.SupportEmail) {
		oldValue["support_email"] = oldCfg.SupportEmail
		newValue["support_email"] = newCfg.SupportEmail
	}
	if oldCfg.MaintenanceMode != newCfg.MaintenanceMode {
		oldValue["maintenance_mode"] = oldCfg.MaintenanceMode
		newValue["maintenance_mode"] = newCfg.MaintenanceMode
	}
	if oldCfg.RegistrationEnabled != newCfg.RegistrationEnabled {
		oldValue["registration_enabled"] = oldCfg.RegistrationEnabled
		newValue["registration_enabled"] = newCfg.RegistrationEnabled
	}
	if oldCfg.DefaultTrafficQuota != newCfg.DefaultTrafficQuota {
		oldValue["default_traffic_quota"] = oldCfg.DefaultTrafficQuota
		newValue["default_traffic_quota"] = newCfg.DefaultTrafficQuota
	}
	if oldCfg.DefaultMaxRules != newCfg.DefaultMaxRules {
		oldValue["default_max_rules"] = oldCfg.DefaultMaxRules
		newValue["default_max_rules"] = newCfg.DefaultMaxRules
	}
	if !reflect.DeepEqual(oldCfg.TelegramConfig, newCfg.TelegramConfig) {
		oldValue["telegram_config"] = oldCfg.TelegramConfig
		newValue["telegram_config"] = newCfg.TelegramConfig
	}
	if !reflect.DeepEqual(oldCfg.ExternalAPIKeys, newCfg.ExternalAPIKeys) {
		oldValue["external_api_keys"] = externalAPIKeysAuditView(oldCfg.ExternalAPIKeys)
		newValue["external_api_keys"] = externalAPIKeysAuditView(newCfg.ExternalAPIKeys)
	}

	if len(newValue) == 0 {
		return
	}

	var userID *uuid.UUID
	if parsed, err := uuid.Parse(strings.TrimSpace(operatorID)); err == nil {
		userID = &parsed
	}

	resourceID := "1"
	_ = s.auditRepo.Create(ctx, &model.AuditLog{
		UserID:       userID,
		Action:       "system.config.update",
		ResourceType: strPtr("system_config"),
		ResourceID:   &resourceID,
		OldValue:     oldValue,
		NewValue:     newValue,
		CreatedAt:    time.Now().UTC(),
	})
}
