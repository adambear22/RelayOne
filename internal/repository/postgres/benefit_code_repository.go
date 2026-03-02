package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

type benefitCodeRepository struct {
	pool *pgxpool.Pool
}

func NewBenefitCodeRepository(pool *pgxpool.Pool) repository.BenefitCodeRepository {
	return &benefitCodeRepository{pool: pool}
}

var _ repository.BenefitCodeRepository = (*benefitCodeRepository)(nil)

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

func (r *benefitCodeRepository) FindByCode(ctx context.Context, code string) (*model.BenefitCode, error) {
	query := `SELECT ` + benefitCodeColumns + ` FROM benefit_codes WHERE code = $1 FOR UPDATE`
	benefitCode, err := scanBenefitCode(r.pool.QueryRow(ctx, query, code))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return benefitCode, nil
}

func (r *benefitCodeRepository) Create(ctx context.Context, benefitCode *model.BenefitCode) error {
	if benefitCode.ID == uuid.Nil {
		benefitCode.ID = uuid.New()
	}
	if benefitCode.CreatedAt.IsZero() {
		benefitCode.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO benefit_codes (
			id, code, vip_level, duration_days, expires_at,
			valid_days, is_used, is_enabled, used_by, used_at,
			created_by, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12
		)
	`

	_, err := r.pool.Exec(
		ctx,
		query,
		benefitCode.ID,
		benefitCode.Code,
		benefitCode.VIPLevel,
		benefitCode.DurationDays,
		benefitCode.ExpiresAt,
		benefitCode.ValidDays,
		benefitCode.IsUsed,
		benefitCode.IsEnabled,
		benefitCode.UsedBy,
		benefitCode.UsedAt,
		benefitCode.CreatedBy,
		benefitCode.CreatedAt,
	)
	return err
}

func (r *benefitCodeRepository) BatchCreate(ctx context.Context, benefitCodes []*model.BenefitCode) error {
	if len(benefitCodes) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	query := `
		INSERT INTO benefit_codes (
			id, code, vip_level, duration_days, expires_at,
			valid_days, is_used, is_enabled, used_by, used_at,
			created_by, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12
		)
	`

	batch := &pgx.Batch{}
	now := time.Now().UTC()
	for _, benefitCode := range benefitCodes {
		if benefitCode.ID == uuid.Nil {
			benefitCode.ID = uuid.New()
		}
		if benefitCode.CreatedAt.IsZero() {
			benefitCode.CreatedAt = now
		}

		batch.Queue(
			query,
			benefitCode.ID,
			benefitCode.Code,
			benefitCode.VIPLevel,
			benefitCode.DurationDays,
			benefitCode.ExpiresAt,
			benefitCode.ValidDays,
			benefitCode.IsUsed,
			benefitCode.IsEnabled,
			benefitCode.UsedBy,
			benefitCode.UsedAt,
			benefitCode.CreatedBy,
			benefitCode.CreatedAt,
		)
	}

	results := tx.SendBatch(ctx, batch)
	for range benefitCodes {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return err
		}
	}
	if err := results.Close(); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *benefitCodeRepository) Update(ctx context.Context, benefitCode *model.BenefitCode) error {
	query := `
		UPDATE benefit_codes
		SET code = $2,
			vip_level = $3,
			duration_days = $4,
			expires_at = $5,
			valid_days = $6,
			is_used = $7,
			is_enabled = $8,
			used_by = $9,
			used_at = $10
		WHERE id = $1
	`

	tag, err := r.pool.Exec(
		ctx,
		query,
		benefitCode.ID,
		benefitCode.Code,
		benefitCode.VIPLevel,
		benefitCode.DurationDays,
		benefitCode.ExpiresAt,
		benefitCode.ValidDays,
		benefitCode.IsUsed,
		benefitCode.IsEnabled,
		benefitCode.UsedBy,
		benefitCode.UsedAt,
	)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *benefitCodeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM benefit_codes WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func scanBenefitCode(src scanTarget) (*model.BenefitCode, error) {
	benefitCode := &model.BenefitCode{}
	err := src.Scan(
		&benefitCode.ID,
		&benefitCode.Code,
		&benefitCode.VIPLevel,
		&benefitCode.DurationDays,
		&benefitCode.ExpiresAt,
		&benefitCode.ValidDays,
		&benefitCode.IsUsed,
		&benefitCode.IsEnabled,
		&benefitCode.UsedBy,
		&benefitCode.UsedAt,
		&benefitCode.CreatedBy,
		&benefitCode.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return benefitCode, nil
}
