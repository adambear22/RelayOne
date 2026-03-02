package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	benefitCodeListDefaultPage = 1
	benefitCodeListDefaultSize = 20
	benefitCodeListMaxPageSize = 200
)

const benefitCodeColumns = `
	id,
	code,
	vip_level,
	duration_days,
	expires_at,
	valid_days,
	is_used,
	is_enabled,
	used_by,
	used_at,
	created_by,
	created_at
`

var (
	ErrBenefitCodeNotFound     = errors.New("benefit code not found")
	ErrBenefitCodeUsed         = errors.New("benefit code already used")
	ErrBenefitCodeExpired      = errors.New("benefit code expired")
	ErrBenefitCodeDisabled     = errors.New("benefit code disabled")
	ErrInvalidBenefitCodeInput = errors.New("invalid benefit code input")
)

type BatchGenerateRequest struct {
	Count        int        `json:"count"`
	VIPLevel     int        `json:"vip_level"`
	DurationDays int        `json:"duration_days"`
	ExpiresAt    *time.Time `json:"expires_at"`
	ValidDays    int        `json:"valid_days"`
	CustomCodes  []string   `json:"custom_codes"`
}

type BenefitCodeListFilter struct {
	VIPLevel  *int
	IsUsed    *bool
	IsEnabled *bool
	Keyword   *string
}

type BenefitCodeService struct {
	benefitCodeRepo repository.BenefitCodeRepository
	auditRepo       repository.AuditRepository
	pool            *pgxpool.Pool
	vipSvc          *VIPService
	sseHub          *sse.SSEHub
	logger          *zap.Logger
}

func NewBenefitCodeService(
	benefitCodeRepo repository.BenefitCodeRepository,
	auditRepo repository.AuditRepository,
	pool *pgxpool.Pool,
	vipSvc *VIPService,
	sseHub *sse.SSEHub,
	logger *zap.Logger,
) *BenefitCodeService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &BenefitCodeService{
		benefitCodeRepo: benefitCodeRepo,
		auditRepo:       auditRepo,
		pool:            pool,
		vipSvc:          vipSvc,
		sseHub:          sseHub,
		logger:          logger,
	}
}

func (s *BenefitCodeService) BatchGenerate(
	ctx context.Context,
	operatorID string,
	req BatchGenerateRequest,
) ([]*model.BenefitCode, error) {
	if s.benefitCodeRepo == nil {
		return nil, errors.New("benefit code repository is nil")
	}
	if s.vipSvc == nil {
		return nil, errors.New("vip service is nil")
	}

	operatorUUID, err := uuid.Parse(strings.TrimSpace(operatorID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	if req.Count <= 0 || req.VIPLevel < 0 || req.DurationDays < 0 {
		return nil, ErrInvalidBenefitCodeInput
	}
	if req.Count > 5000 {
		return nil, ErrInvalidBenefitCodeInput
	}

	if req.ValidDays <= 0 {
		req.ValidDays = 30
	}

	if _, err := s.vipSvc.GetLevel(ctx, req.VIPLevel); err != nil {
		return nil, err
	}

	codes, err := buildBatchCodes(req)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	items := make([]*model.BenefitCode, 0, len(codes))
	for _, code := range codes {
		items = append(items, &model.BenefitCode{
			ID:           uuid.New(),
			Code:         code,
			VIPLevel:     req.VIPLevel,
			DurationDays: req.DurationDays,
			ExpiresAt:    cloneTimePtr(req.ExpiresAt),
			ValidDays:    req.ValidDays,
			IsUsed:       false,
			IsEnabled:    true,
			CreatedBy:    operatorUUID,
			CreatedAt:    now,
		})
	}

	if err := s.benefitCodeRepo.BatchCreate(ctx, items); err != nil {
		return nil, err
	}

	if s.auditRepo != nil {
		_ = s.auditRepo.Create(ctx, &model.AuditLog{
			UserID:       &operatorUUID,
			Action:       "benefit_code.batch_generate",
			ResourceType: strPtr("benefit_code"),
			NewValue: map[string]interface{}{
				"count":         len(items),
				"vip_level":     req.VIPLevel,
				"duration_days": req.DurationDays,
				"valid_days":    req.ValidDays,
			},
			CreatedAt: now,
		})
	}

	return items, nil
}

func (s *BenefitCodeService) Redeem(ctx context.Context, userID, code string) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}
	if s.vipSvc == nil {
		return errors.New("vip service is nil")
	}

	userUUID, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return ErrInvalidUserID
	}

	normalizedCode := strings.TrimSpace(code)
	if normalizedCode == "" {
		return ErrInvalidBenefitCodeInput
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	benefitCode, err := s.findByCodeForUpdateTx(ctx, tx, normalizedCode)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if !benefitCode.IsEnabled {
		return ErrBenefitCodeDisabled
	}
	if benefitCode.IsUsed {
		return ErrBenefitCodeUsed
	}
	if benefitCode.ExpiresAt != nil && !benefitCode.ExpiresAt.After(now) {
		return ErrBenefitCodeExpired
	}

	if _, err := tx.Exec(
		ctx,
		`UPDATE benefit_codes
		    SET is_used = TRUE,
		        used_by = $2,
		        used_at = $3
		  WHERE id = $1`,
		benefitCode.ID,
		userUUID,
		now,
	); err != nil {
		return err
	}

	upgradeResult, err := s.vipSvc.upgradeUserTx(
		ctx,
		tx,
		userUUID,
		benefitCode.VIPLevel,
		benefitCode.DurationDays,
	)
	if err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	s.vipSvc.writeUpgradeAudit(ctx, userID, upgradeResult)
	s.writeRedeemAudit(ctx, userUUID, benefitCode)

	if s.sseHub != nil {
		s.sseHub.SendToUser(userID, sse.NewEvent(sse.EventTrafficUpdate, map[string]interface{}{
			"user_id":       userID,
			"code":          benefitCode.Code,
			"vip_level":     benefitCode.VIPLevel,
			"duration_days": benefitCode.DurationDays,
			"status":        "redeemed",
			"ts":            time.Now().UTC().Format(time.RFC3339Nano),
		}))
	}

	return nil
}

func (s *BenefitCodeService) BatchUpdateStatus(ctx context.Context, ids []string, enabled bool) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	uids, err := parseUUIDList(ids)
	if err != nil {
		return err
	}
	if len(uids) == 0 {
		return ErrInvalidBenefitCodeInput
	}

	_, err = s.pool.Exec(
		ctx,
		`UPDATE benefit_codes
		    SET is_enabled = $2
		  WHERE id = ANY($1)`,
		uids,
		enabled,
	)
	return err
}

func (s *BenefitCodeService) BatchDelete(ctx context.Context, ids []string) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	uids, err := parseUUIDList(ids)
	if err != nil {
		return err
	}
	if len(uids) == 0 {
		return ErrInvalidBenefitCodeInput
	}

	_, err = s.pool.Exec(
		ctx,
		`DELETE FROM benefit_codes
		  WHERE id = ANY($1)
		    AND is_used = FALSE`,
		uids,
	)
	return err
}

func (s *BenefitCodeService) List(
	ctx context.Context,
	page, pageSize int,
	filter BenefitCodeListFilter,
) ([]*model.BenefitCode, int64, error) {
	if s.pool == nil {
		return nil, 0, errors.New("database pool is nil")
	}

	page, pageSize = normalizeBenefitCodeListPage(page, pageSize)
	args := make([]any, 0, 8)
	conditions := make([]string, 0, 4)

	if filter.VIPLevel != nil {
		args = append(args, *filter.VIPLevel)
		conditions = append(conditions, fmt.Sprintf("vip_level = $%d", len(args)))
	}
	if filter.IsUsed != nil {
		args = append(args, *filter.IsUsed)
		conditions = append(conditions, fmt.Sprintf("is_used = $%d", len(args)))
	}
	if filter.IsEnabled != nil {
		args = append(args, *filter.IsEnabled)
		conditions = append(conditions, fmt.Sprintf("is_enabled = $%d", len(args)))
	}
	if filter.Keyword != nil {
		keyword := "%" + strings.TrimSpace(*filter.Keyword) + "%"
		args = append(args, keyword)
		conditions = append(conditions, fmt.Sprintf("code ILIKE $%d", len(args)))
	}

	query := `SELECT ` + benefitCodeColumns + ` FROM benefit_codes`
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

	items := make([]*model.BenefitCode, 0, pageSize)
	for rows.Next() {
		item, scanErr := scanBenefitCode(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	countArgs := args[:len(args)-2]
	countQuery := `SELECT COUNT(*) FROM benefit_codes`
	if len(conditions) > 0 {
		countQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	if err := s.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *BenefitCodeService) ListRedeemHistory(
	ctx context.Context,
	userID string,
	page, pageSize int,
) ([]*model.BenefitCode, int64, error) {
	if s.pool == nil {
		return nil, 0, errors.New("database pool is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return nil, 0, ErrInvalidUserID
	}

	page, pageSize = normalizeBenefitCodeListPage(page, pageSize)
	rows, err := s.pool.Query(
		ctx,
		`SELECT `+benefitCodeColumns+`
		   FROM benefit_codes
		  WHERE is_used = TRUE
		    AND used_by = $1
		  ORDER BY used_at DESC NULLS LAST, created_at DESC
		  LIMIT $2 OFFSET $3`,
		uid,
		pageSize,
		(page-1)*pageSize,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]*model.BenefitCode, 0, pageSize)
	for rows.Next() {
		item, scanErr := scanBenefitCode(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int64
	if err := s.pool.QueryRow(
		ctx,
		`SELECT COUNT(*)
		   FROM benefit_codes
		  WHERE is_used = TRUE
		    AND used_by = $1`,
		uid,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *BenefitCodeService) findByCodeForUpdateTx(ctx context.Context, tx pgx.Tx, code string) (*model.BenefitCode, error) {
	item, err := scanBenefitCode(tx.QueryRow(
		ctx,
		`SELECT `+benefitCodeColumns+` FROM benefit_codes WHERE code = $1 FOR UPDATE`,
		code,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrBenefitCodeNotFound
		}
		return nil, err
	}
	return item, nil
}

func (s *BenefitCodeService) writeRedeemAudit(ctx context.Context, userID uuid.UUID, benefitCode *model.BenefitCode) {
	if s.auditRepo == nil || benefitCode == nil {
		return
	}

	resourceID := benefitCode.ID.String()
	_ = s.auditRepo.Create(ctx, &model.AuditLog{
		UserID:       &userID,
		Action:       "benefit_code.redeem",
		ResourceType: strPtr("benefit_code"),
		ResourceID:   &resourceID,
		NewValue: map[string]interface{}{
			"code":          benefitCode.Code,
			"vip_level":     benefitCode.VIPLevel,
			"duration_days": benefitCode.DurationDays,
		},
		CreatedAt: time.Now().UTC(),
	})
}

func normalizeBenefitCodeListPage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = benefitCodeListDefaultPage
	}
	if pageSize <= 0 {
		pageSize = benefitCodeListDefaultSize
	}
	if pageSize > benefitCodeListMaxPageSize {
		pageSize = benefitCodeListMaxPageSize
	}
	return page, pageSize
}

func scanBenefitCode(src rowScanner) (*model.BenefitCode, error) {
	item := &model.BenefitCode{}
	if err := src.Scan(
		&item.ID,
		&item.Code,
		&item.VIPLevel,
		&item.DurationDays,
		&item.ExpiresAt,
		&item.ValidDays,
		&item.IsUsed,
		&item.IsEnabled,
		&item.UsedBy,
		&item.UsedAt,
		&item.CreatedBy,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	return item, nil
}

func buildBatchCodes(req BatchGenerateRequest) ([]string, error) {
	normalized := make([]string, 0, len(req.CustomCodes))
	for _, raw := range req.CustomCodes {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}

	codes := make([]string, 0, req.Count)
	switch {
	case len(normalized) == 0:
		for i := 0; i < req.Count; i++ {
			codes = append(codes, randomCode8())
		}
	case len(normalized) == 1 && req.Count > 1:
		prefix := normalized[0]
		if len(prefix) > 56 {
			return nil, ErrInvalidBenefitCodeInput
		}
		for i := 0; i < req.Count; i++ {
			codes = append(codes, prefix+randomCode8())
		}
	case len(normalized) == req.Count:
		codes = append(codes, normalized...)
	default:
		return nil, ErrInvalidBenefitCodeInput
	}

	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		if len(code) > 64 {
			return nil, ErrInvalidBenefitCodeInput
		}
		if _, ok := seen[code]; ok {
			return nil, ErrInvalidBenefitCodeInput
		}
		seen[code] = struct{}{}
	}

	return codes, nil
}

func randomCode8() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
}

func parseUUIDList(ids []string) ([]uuid.UUID, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	seen := make(map[uuid.UUID]struct{}, len(ids))
	result := make([]uuid.UUID, 0, len(ids))
	for _, raw := range ids {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		id, err := uuid.Parse(trimmed)
		if err != nil {
			return nil, ErrInvalidBenefitCodeInput
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}

	return result, nil
}
