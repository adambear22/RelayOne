package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

type trafficRepository struct {
	pool *pgxpool.Pool
}

func NewTrafficRepository(pool *pgxpool.Pool) repository.TrafficRepository {
	return &trafficRepository{pool: pool}
}

var _ repository.TrafficRepository = (*trafficRepository)(nil)

func (r *trafficRepository) Upsert(ctx context.Context, traffic *model.TrafficHourly) error {
	if traffic.Hour.IsZero() {
		traffic.Hour = time.Now().UTC().Truncate(time.Hour)
	}

	query := `
		INSERT INTO traffic_hourly (
			rule_id,
			user_id,
			hour,
			bytes_in,
			bytes_out,
			bytes_total,
			ratio_applied
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (rule_id, hour)
		DO UPDATE SET
			user_id = COALESCE(EXCLUDED.user_id, traffic_hourly.user_id),
			bytes_in = traffic_hourly.bytes_in + EXCLUDED.bytes_in,
			bytes_out = traffic_hourly.bytes_out + EXCLUDED.bytes_out,
			bytes_total = traffic_hourly.bytes_total + EXCLUDED.bytes_total,
			ratio_applied = EXCLUDED.ratio_applied
	`

	_, err := r.pool.Exec(
		ctx,
		query,
		traffic.RuleID,
		traffic.UserID,
		traffic.Hour,
		traffic.BytesIn,
		traffic.BytesOut,
		traffic.BytesTotal,
		traffic.RatioApplied,
	)
	return err
}

func (r *trafficRepository) SumByUser(ctx context.Context, userID uuid.UUID, period repository.TrafficPeriod, referenceTime time.Time) (int64, error) {
	start, end, err := periodRange(period, referenceTime)
	if err != nil {
		return 0, err
	}

	query := `
		SELECT COALESCE(SUM(bytes_total), 0)
		FROM traffic_hourly
		WHERE user_id = $1
		  AND hour >= $2
		  AND hour < $3
	`

	var total int64
	err = r.pool.QueryRow(ctx, query, userID, start, end).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

func (r *trafficRepository) SumByRule(ctx context.Context, ruleID uuid.UUID, start, end time.Time) (int64, error) {
	query := `
		SELECT COALESCE(SUM(bytes_total), 0)
		FROM traffic_hourly
		WHERE rule_id = $1
		  AND hour >= $2
		  AND hour < $3
	`

	var total int64
	err := r.pool.QueryRow(ctx, query, ruleID, start, end).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

func periodRange(period repository.TrafficPeriod, referenceTime time.Time) (time.Time, time.Time, error) {
	reference := referenceTime.UTC()
	year, month, day := reference.Date()

	switch period {
	case repository.TrafficPeriodDay:
		start := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 0, 1), nil
	case repository.TrafficPeriodMonth:
		start := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 1, 0), nil
	default:
		return time.Time{}, time.Time{}, fmt.Errorf("unsupported traffic period: %s", period)
	}
}
