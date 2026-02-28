package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

const (
	auditListDefaultPage = 1
	auditListDefaultSize = 20
	auditListMaxPageSize = 200
)

var (
	ErrInvalidAuditInput = errors.New("invalid audit input")
)

type AuditEntry struct {
	UserID       *string                `json:"user_id,omitempty"`
	Action       string                 `json:"action"`
	ResourceType *string                `json:"resource_type,omitempty"`
	ResourceID   *string                `json:"resource_id,omitempty"`
	OldValue     map[string]interface{} `json:"old_value,omitempty"`
	NewValue     map[string]interface{} `json:"new_value,omitempty"`
	IPAddress    *string                `json:"ip_address,omitempty"`
	UserAgent    *string                `json:"user_agent,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

type AuditFilter struct {
	UserID       *string    `json:"user_id,omitempty"`
	ResourceType *string    `json:"resource_type,omitempty"`
	ResourceID   *string    `json:"resource_id,omitempty"`
	Action       *string    `json:"action,omitempty"`
	IPAddress    *string    `json:"ip_address,omitempty"`
	From         *time.Time `json:"from,omitempty"`
	To           *time.Time `json:"to,omitempty"`
}

type AuditService struct {
	auditRepo repository.AuditRepository
	pool      *pgxpool.Pool
}

func NewAuditService(auditRepo repository.AuditRepository, pool *pgxpool.Pool) *AuditService {
	return &AuditService{
		auditRepo: auditRepo,
		pool:      pool,
	}
}

func (s *AuditService) Log(ctx context.Context, entry AuditEntry) error {
	if s.auditRepo == nil {
		return errors.New("audit repository is nil")
	}

	action := strings.TrimSpace(entry.Action)
	if action == "" {
		return ErrInvalidAuditInput
	}

	var userID *uuid.UUID
	if entry.UserID != nil && strings.TrimSpace(*entry.UserID) != "" {
		parsed, err := uuid.Parse(strings.TrimSpace(*entry.UserID))
		if err != nil {
			return ErrInvalidUserID
		}
		userID = &parsed
	}

	logItem := &model.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: trimAuditStringPtr(entry.ResourceType),
		ResourceID:   trimAuditStringPtr(entry.ResourceID),
		OldValue:     entry.OldValue,
		NewValue:     entry.NewValue,
		IPAddress:    trimAuditStringPtr(entry.IPAddress),
		UserAgent:    trimAuditStringPtr(entry.UserAgent),
		CreatedAt:    entry.CreatedAt.UTC(),
	}
	if logItem.CreatedAt.IsZero() {
		logItem.CreatedAt = time.Now().UTC()
	}

	return s.auditRepo.Create(ctx, logItem)
}

func (s *AuditService) List(
	ctx context.Context,
	filter AuditFilter,
	page, pageSize int,
) ([]*model.AuditLog, int64, error) {
	if s.pool == nil {
		return nil, 0, errors.New("database pool is nil")
	}

	page, pageSize = normalizeAuditPagination(page, pageSize)

	args := make([]any, 0, 12)
	conditions := make([]string, 0, 7)

	if filter.UserID != nil && strings.TrimSpace(*filter.UserID) != "" {
		uid, err := uuid.Parse(strings.TrimSpace(*filter.UserID))
		if err != nil {
			return nil, 0, ErrInvalidUserID
		}
		args = append(args, uid)
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", len(args)))
	}
	if filter.ResourceType != nil && strings.TrimSpace(*filter.ResourceType) != "" {
		args = append(args, strings.TrimSpace(*filter.ResourceType))
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", len(args)))
	}
	if filter.ResourceID != nil && strings.TrimSpace(*filter.ResourceID) != "" {
		args = append(args, strings.TrimSpace(*filter.ResourceID))
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", len(args)))
	}
	if filter.Action != nil && strings.TrimSpace(*filter.Action) != "" {
		args = append(args, strings.TrimSpace(*filter.Action))
		conditions = append(conditions, fmt.Sprintf("action = $%d", len(args)))
	}
	if filter.IPAddress != nil && strings.TrimSpace(*filter.IPAddress) != "" {
		args = append(args, strings.TrimSpace(*filter.IPAddress))
		conditions = append(conditions, fmt.Sprintf("(host(ip_address) = $%d OR ip_address::text = $%d)", len(args), len(args)))
	}
	if filter.From != nil {
		from := filter.From.UTC()
		args = append(args, from)
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if filter.To != nil {
		to := filter.To.UTC()
		args = append(args, to)
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", len(args)))
	}

	baseQuery := `SELECT id, user_id, action, resource_type, resource_id, old_value, new_value, ip_address, user_agent, created_at FROM audit_logs`
	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	queryArgs := append([]any{}, args...)
	queryArgs = append(queryArgs, pageSize, (page-1)*pageSize)
	query := baseQuery + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(queryArgs)-1, len(queryArgs))

	rows, err := s.pool.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]*model.AuditLog, 0, pageSize)
	for rows.Next() {
		item, scanErr := scanAuditLogRow(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	countQuery := `SELECT COUNT(*) FROM audit_logs`
	if len(conditions) > 0 {
		countQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func normalizeAuditPagination(page, pageSize int) (int, int) {
	if page <= 0 {
		page = auditListDefaultPage
	}
	if pageSize <= 0 {
		pageSize = auditListDefaultSize
	}
	if pageSize > auditListMaxPageSize {
		pageSize = auditListMaxPageSize
	}
	return page, pageSize
}

func trimAuditStringPtr(v *string) *string {
	if v == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*v)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func scanAuditLogRow(src rowScanner) (*model.AuditLog, error) {
	item := &model.AuditLog{}
	var oldRaw []byte
	var newRaw []byte

	if err := src.Scan(
		&item.ID,
		&item.UserID,
		&item.Action,
		&item.ResourceType,
		&item.ResourceID,
		&oldRaw,
		&newRaw,
		&item.IPAddress,
		&item.UserAgent,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}

	if len(oldRaw) > 0 {
		if err := json.Unmarshal(oldRaw, &item.OldValue); err != nil {
			return nil, err
		}
	}
	if len(newRaw) > 0 {
		if err := json.Unmarshal(newRaw, &item.NewValue); err != nil {
			return nil, err
		}
	}

	return item, nil
}
