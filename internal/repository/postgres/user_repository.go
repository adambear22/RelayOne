package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

type userRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) repository.UserRepository {
	return &userRepository{pool: pool}
}

var _ repository.UserRepository = (*userRepository)(nil)

type scanTarget interface {
	Scan(dest ...any) error
}

const userColumns = `
	id,
	username,
	password_hash,
	email,
	role,
	status,
	telegram_id,
	telegram_username,
	vip_level,
	vip_expires_at,
	traffic_quota,
	traffic_used,
	bandwidth_limit,
	max_rules,
	permissions,
	created_at,
	updated_at
`

func (r *userRepository) FindByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	user, err := scanUser(r.pool.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *userRepository) FindByUsername(ctx context.Context, username string) (*model.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE username = $1`
	user, err := scanUser(r.pool.QueryRow(ctx, query, username))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *userRepository) FindByTelegramID(ctx context.Context, telegramID int64) (*model.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE telegram_id = $1`
	user, err := scanUser(r.pool.QueryRow(ctx, query, telegramID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *userRepository) Create(ctx context.Context, user *model.User) error {
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	now := time.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = user.CreatedAt
	}

	query := `
		INSERT INTO users (
			id, username, password_hash, email, role, status,
			telegram_id, telegram_username, vip_level, vip_expires_at,
			traffic_quota, traffic_used, bandwidth_limit, max_rules,
			permissions, created_at, updated_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17
		)
	`

	_, err := r.pool.Exec(
		ctx,
		query,
		user.ID,
		user.Username,
		user.PasswordHash,
		user.Email,
		user.Role,
		user.Status,
		user.TelegramID,
		user.TelegramUsername,
		user.VIPLevel,
		user.VIPExpiresAt,
		user.TrafficQuota,
		user.TrafficUsed,
		user.BandwidthLimit,
		user.MaxRules,
		user.Permissions,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

func (r *userRepository) Update(ctx context.Context, user *model.User) error {
	user.UpdatedAt = time.Now().UTC()
	query := `
		UPDATE users
		SET username = $2,
			password_hash = $3,
			email = $4,
			role = $5,
			status = $6,
			telegram_id = $7,
			telegram_username = $8,
			vip_level = $9,
			vip_expires_at = $10,
			traffic_quota = $11,
			traffic_used = $12,
			bandwidth_limit = $13,
			max_rules = $14,
			permissions = $15,
			updated_at = $16
		WHERE id = $1
	`

	tag, err := r.pool.Exec(
		ctx,
		query,
		user.ID,
		user.Username,
		user.PasswordHash,
		user.Email,
		user.Role,
		user.Status,
		user.TelegramID,
		user.TelegramUsername,
		user.VIPLevel,
		user.VIPExpiresAt,
		user.TrafficQuota,
		user.TrafficUsed,
		user.BandwidthLimit,
		user.MaxRules,
		user.Permissions,
		user.UpdatedAt,
	)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *userRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status model.UserStatus) error {
	query := `UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, status)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *userRepository) UpdateTrafficUsed(ctx context.Context, id uuid.UUID, delta int64) error {
	query := `
		UPDATE users
		SET traffic_used = traffic_used + $2,
			updated_at = NOW()
		WHERE id = $1
	`
	tag, err := r.pool.Exec(ctx, query, id, delta)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *userRepository) List(ctx context.Context, filter repository.UserListFilter) ([]*model.User, error) {
	limit, offset := normalizePagination(filter.Pagination)

	args := make([]any, 0, 6)
	conditions := buildUserListConditions(filter, &args)

	var builder strings.Builder
	builder.WriteString("SELECT ")
	builder.WriteString(userColumns)
	builder.WriteString(" FROM users")

	if len(conditions) > 0 {
		builder.WriteString(" WHERE ")
		builder.WriteString(strings.Join(conditions, " AND "))
	}

	args = append(args, limit, offset)
	_, _ = fmt.Fprintf(&builder, " ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, builder.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]*model.User, 0, limit)
	for rows.Next() {
		item, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (r *userRepository) Count(ctx context.Context, filter repository.UserListFilter) (int64, error) {
	args := make([]any, 0, 4)
	conditions := buildUserListConditions(filter, &args)

	var builder strings.Builder
	builder.WriteString("SELECT COUNT(*) FROM users")
	if len(conditions) > 0 {
		builder.WriteString(" WHERE ")
		builder.WriteString(strings.Join(conditions, " AND "))
	}

	var total int64
	if err := r.pool.QueryRow(ctx, builder.String(), args...).Scan(&total); err != nil {
		return 0, err
	}

	return total, nil
}

func buildUserListConditions(filter repository.UserListFilter, args *[]any) []string {
	conditions := make([]string, 0, 3)

	if filter.Role != nil {
		*args = append(*args, *filter.Role)
		conditions = append(conditions, fmt.Sprintf("role = $%d", len(*args)))
	}
	if filter.Status != nil {
		*args = append(*args, *filter.Status)
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(*args)))
	}
	if filter.Keyword != nil {
		keyword := "%" + strings.TrimSpace(*filter.Keyword) + "%"
		*args = append(*args, keyword)
		argPos := len(*args)
		conditions = append(conditions, fmt.Sprintf("(username ILIKE $%d OR email ILIKE $%d)", argPos, argPos))
	}

	return conditions
}

func scanUser(src scanTarget) (*model.User, error) {
	user := &model.User{}
	err := src.Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.Email,
		&user.Role,
		&user.Status,
		&user.TelegramID,
		&user.TelegramUsername,
		&user.VIPLevel,
		&user.VIPExpiresAt,
		&user.TrafficQuota,
		&user.TrafficUsed,
		&user.BandwidthLimit,
		&user.MaxRules,
		&user.Permissions,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return user, nil
}
