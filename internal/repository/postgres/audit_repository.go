package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

type auditRepository struct {
	pool *pgxpool.Pool
}

func NewAuditRepository(pool *pgxpool.Pool) repository.AuditRepository {
	return &auditRepository{pool: pool}
}

var _ repository.AuditRepository = (*auditRepository)(nil)

const auditColumns = `
	id,
	user_id,
	action,
	resource_type,
	resource_id,
	old_value,
	new_value,
	ip_address,
	user_agent,
	created_at
`

func (r *auditRepository) Create(ctx context.Context, log *model.AuditLog) error {
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}

	oldValue, err := encodeJSONMap(log.OldValue)
	if err != nil {
		return err
	}
	newValue, err := encodeJSONMap(log.NewValue)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO audit_logs (
			user_id,
			action,
			resource_type,
			resource_id,
			old_value,
			new_value,
			ip_address,
			user_agent,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`

	return r.pool.QueryRow(
		ctx,
		query,
		log.UserID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		oldValue,
		newValue,
		log.IPAddress,
		log.UserAgent,
		log.CreatedAt,
	).Scan(&log.ID)
}

func (r *auditRepository) List(ctx context.Context, filter repository.AuditListFilter) ([]*model.AuditLog, error) {
	limit, offset := normalizePagination(filter.Pagination)

	args := make([]any, 0, 8)
	conditions := make([]string, 0, 4)

	if filter.UserID != nil {
		args = append(args, *filter.UserID)
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", len(args)))
	}
	if filter.ResourceType != nil {
		args = append(args, *filter.ResourceType)
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", len(args)))
	}
	if filter.StartTime != nil {
		args = append(args, *filter.StartTime)
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if filter.EndTime != nil {
		args = append(args, *filter.EndTime)
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", len(args)))
	}

	var builder strings.Builder
	builder.WriteString("SELECT ")
	builder.WriteString(auditColumns)
	builder.WriteString(" FROM audit_logs")

	if len(conditions) > 0 {
		builder.WriteString(" WHERE ")
		builder.WriteString(strings.Join(conditions, " AND "))
	}

	args = append(args, limit, offset)
	builder.WriteString(fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)))

	rows, err := r.pool.Query(ctx, builder.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]*model.AuditLog, 0, limit)
	for rows.Next() {
		item, err := scanAuditLog(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return logs, nil
}

func scanAuditLog(src scanTarget) (*model.AuditLog, error) {
	log := &model.AuditLog{}
	var oldValueRaw []byte
	var newValueRaw []byte

	err := src.Scan(
		&log.ID,
		&log.UserID,
		&log.Action,
		&log.ResourceType,
		&log.ResourceID,
		&oldValueRaw,
		&newValueRaw,
		&log.IPAddress,
		&log.UserAgent,
		&log.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	log.OldValue, err = decodeJSONMap(oldValueRaw)
	if err != nil {
		return nil, err
	}
	log.NewValue, err = decodeJSONMap(newValueRaw)
	if err != nil {
		return nil, err
	}

	return log, nil
}
