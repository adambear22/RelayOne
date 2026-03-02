package service

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/event"
	"nodepass-hub/internal/metrics"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

const (
	trafficFlushInterval = 60 * time.Second
)

const (
	trafficStatsByHourQuery = `SELECT date_trunc('hour', hour) AS bucket,
	        COALESCE(SUM(bytes_in), 0),
	        COALESCE(SUM(bytes_out), 0),
	        COALESCE(SUM(bytes_total), 0)
	   FROM traffic_hourly
	  WHERE user_id = $1
	    AND hour >= $2
	    AND hour < $3
	  GROUP BY bucket
	  ORDER BY bucket ASC`
	trafficStatsByDayQuery = `SELECT date_trunc('day', hour) AS bucket,
	        COALESCE(SUM(bytes_in), 0),
	        COALESCE(SUM(bytes_out), 0),
	        COALESCE(SUM(bytes_total), 0)
	   FROM traffic_hourly
	  WHERE user_id = $1
	    AND hour >= $2
	    AND hour < $3
	  GROUP BY bucket
	  ORDER BY bucket ASC`
	trafficStatsByMonthQuery = `SELECT date_trunc('month', hour) AS bucket,
	        COALESCE(SUM(bytes_in), 0),
	        COALESCE(SUM(bytes_out), 0),
	        COALESCE(SUM(bytes_total), 0)
	   FROM traffic_hourly
	  WHERE user_id = $1
	    AND hour >= $2
	    AND hour < $3
	  GROUP BY bucket
	  ORDER BY bucket ASC`
)

var (
	ErrInvalidTrafficInput = errors.New("invalid traffic input")
)

type TrafficRecord struct {
	RuleID    string    `json:"rule_id"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Timestamp time.Time `json:"timestamp"`
}

type TrafficStat struct {
	Time       time.Time `json:"time"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	BytesTotal int64     `json:"bytes_total"`
}

type DailyStat struct {
	Day        time.Time `json:"day"`
	BytesTotal int64     `json:"bytes_total"`
}

type MonthlyStat struct {
	Month      time.Time `json:"month"`
	BytesTotal int64     `json:"bytes_total"`
}

type HourlyPoint struct {
	Hour       time.Time `json:"hour"`
	BytesTotal int64     `json:"bytes_total"`
}

type TopUserTraffic struct {
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	TrafficUsed  int64  `json:"traffic_used"`
	TrafficQuota int64  `json:"traffic_quota"`
}

type TopRuleTraffic struct {
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	OwnerID    string `json:"owner_id"`
	BytesTotal int64  `json:"bytes_total"`
}

type TrafficOverview struct {
	TodayTotal int64            `json:"today_total"`
	MonthTotal int64            `json:"month_total"`
	Top10Users []TopUserTraffic `json:"top10_users"`
	Top10Rules []TopRuleTraffic `json:"top10_rules"`
}

type TrafficService interface {
	HandleReport(ctx context.Context, agentID string, records []TrafficRecord) error
	QueryStats(ctx context.Context, userID string, granularity string, from, to time.Time) ([]TrafficStat, error)
	QueryUserDailyStats(ctx context.Context, userID string, days int) ([]*DailyStat, error)
	QueryUserMonthlyStats(ctx context.Context, userID string, months int) ([]*MonthlyStat, error)
	QueryRuleStats(ctx context.Context, ruleID string, from, to time.Time) ([]*HourlyPoint, error)
	AdminOverview(ctx context.Context) (*TrafficOverview, error)
	ResetUserQuota(ctx context.Context, userID string) error
	ResetAllMonthlyQuotas(ctx context.Context) (int64, error)
	BatchSyncQuota(ctx context.Context) error
}

type trafficService struct {
	trafficRepo repository.TrafficRepository
	userRepo    repository.UserRepository
	ruleRepo    repository.RuleRepository
	auditRepo   repository.AuditRepository
	pool        *pgxpool.Pool
	eventBus    *event.Bus
	logger      *zap.Logger

	bufferMu        sync.Mutex
	primaryBuffer   map[hourlyUpsertKey]hourlyUpsertRecord
	secondaryBuffer map[hourlyUpsertKey]hourlyUpsertRecord
	stopCh          chan struct{}

	lookupBillingInfoFn    func(ctx context.Context, ruleID uuid.UUID) (*billingInfo, error)
	incrementUserTrafficFn func(ctx context.Context, userID uuid.UUID, delta int64) (int64, int64, error)
}

type billingInfo struct {
	OwnerID       uuid.UUID
	IngressNodeID uuid.UUID
	NodeRatio     float64
	VIPRatio      float64
}

type hourlyUpsertRecord struct {
	RuleID       uuid.UUID
	UserID       uuid.UUID
	Hour         time.Time
	BytesIn      int64
	BytesOut     int64
	BytesTotal   int64
	RatioApplied float64
}

type hourlyUpsertKey struct {
	RuleID uuid.UUID
	Hour   time.Time
}

func NewTrafficService(
	trafficRepo repository.TrafficRepository,
	userRepo repository.UserRepository,
	ruleRepo repository.RuleRepository,
	auditRepo repository.AuditRepository,
	pool *pgxpool.Pool,
	eventBus *event.Bus,
	logger *zap.Logger,
) TrafficService {
	if logger == nil {
		logger = zap.NewNop()
	}

	svc := &trafficService{
		trafficRepo:     trafficRepo,
		userRepo:        userRepo,
		ruleRepo:        ruleRepo,
		auditRepo:       auditRepo,
		pool:            pool,
		eventBus:        eventBus,
		logger:          logger,
		primaryBuffer:   make(map[hourlyUpsertKey]hourlyUpsertRecord, 1024),
		secondaryBuffer: make(map[hourlyUpsertKey]hourlyUpsertRecord, 1024),
		stopCh:          make(chan struct{}),
	}

	go svc.batchWorker()
	return svc
}

func (s *trafficService) HandleReport(ctx context.Context, agentID string, records []TrafficRecord) error {
	startedAt := time.Now()
	var totalIn int64
	var totalOut int64
	var totalBilled int64
	defer func() {
		metrics.ObserveTrafficReportDuration(time.Since(startedAt))
		metrics.AddTrafficBytes(totalIn, totalOut, totalBilled)
	}()

	if len(records) == 0 {
		return nil
	}
	if s.pool == nil && (s.lookupBillingInfoFn == nil || s.incrementUserTrafficFn == nil) {
		return errors.New("database pool is nil")
	}
	if strings.TrimSpace(agentID) == "" {
		return ErrInvalidTrafficInput
	}

	for _, record := range records {
		if strings.TrimSpace(record.RuleID) == "" {
			continue
		}

		ruleID, err := uuid.Parse(strings.TrimSpace(record.RuleID))
		if err != nil {
			continue
		}

		info, err := s.lookupBillingInfoRecord(ctx, ruleID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				continue
			}
			return err
		}

		baseBytes := record.BytesIn + record.BytesOut
		if baseBytes <= 0 {
			continue
		}

		ratio := info.NodeRatio * info.VIPRatio
		if ratio <= 0 {
			ratio = 1.0
		}
		billedBytes := int64(math.Round(float64(baseBytes) * ratio))
		if billedBytes < 0 {
			billedBytes = 0
		}
		totalIn += record.BytesIn
		totalOut += record.BytesOut
		totalBilled += billedBytes

		used, quota, err := s.incrementUserTraffic(ctx, info.OwnerID, billedBytes)
		if err != nil {
			return err
		}

		ts := record.Timestamp.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		s.pushHourlyRecord(hourlyUpsertRecord{
			RuleID:       ruleID,
			UserID:       info.OwnerID,
			Hour:         ts.Truncate(time.Hour),
			BytesIn:      record.BytesIn,
			BytesOut:     record.BytesOut,
			BytesTotal:   billedBytes,
			RatioApplied: ratio,
		})

		if quota > 0 && used >= quota && s.eventBus != nil {
			s.eventBus.Publish(event.EventUserQuotaExceeded, event.QuotaExceededPayload{
				UserID:       info.OwnerID.String(),
				TrafficUsed:  used,
				TrafficQuota: quota,
			})
		}
	}

	return nil
}

func (s *trafficService) lookupBillingInfoRecord(ctx context.Context, ruleID uuid.UUID) (*billingInfo, error) {
	if s.lookupBillingInfoFn != nil {
		return s.lookupBillingInfoFn(ctx, ruleID)
	}
	return s.lookupBillingInfo(ctx, ruleID)
}

func (s *trafficService) incrementUserTraffic(ctx context.Context, userID uuid.UUID, delta int64) (int64, int64, error) {
	if s.incrementUserTrafficFn != nil {
		return s.incrementUserTrafficFn(ctx, userID, delta)
	}
	return s.incrementUserTrafficUsed(ctx, userID, delta)
}

func (s *trafficService) QueryStats(ctx context.Context, userID string, granularity string, from, to time.Time) ([]TrafficStat, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	gran := strings.ToLower(strings.TrimSpace(granularity))
	if gran == "" {
		gran = "hour"
	}
	if gran != "hour" && gran != "day" && gran != "month" {
		return nil, ErrInvalidTrafficInput
	}

	start := from.UTC()
	end := to.UTC()
	if start.IsZero() {
		start = time.Now().UTC().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now().UTC()
	}
	if !end.After(start) {
		return nil, ErrInvalidTrafficInput
	}

	var query string
	switch gran {
	case "hour":
		query = trafficStatsByHourQuery
	case "day":
		query = trafficStatsByDayQuery
	case "month":
		query = trafficStatsByMonthQuery
	default:
		return nil, ErrInvalidTrafficInput
	}

	rows, err := s.pool.Query(ctx, query, uid, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make([]TrafficStat, 0, 64)
	for rows.Next() {
		var item TrafficStat
		if err := rows.Scan(&item.Time, &item.BytesIn, &item.BytesOut, &item.BytesTotal); err != nil {
			return nil, err
		}
		stats = append(stats, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stats, nil
}

func (s *trafficService) QueryUserDailyStats(ctx context.Context, userID string, days int) ([]*DailyStat, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	if days <= 0 {
		days = 30
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT date_trunc('day', hour) AS bucket,
		        COALESCE(SUM(bytes_total), 0)
		   FROM traffic_hourly
		  WHERE user_id = $1
		    AND hour >= NOW() - ($2::int * INTERVAL '1 day')
		  GROUP BY bucket
		  ORDER BY bucket ASC`,
		uid,
		days,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*DailyStat, 0, days)
	for rows.Next() {
		item := &DailyStat{}
		if err := rows.Scan(&item.Day, &item.BytesTotal); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func (s *trafficService) QueryUserMonthlyStats(ctx context.Context, userID string, months int) ([]*MonthlyStat, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	if months <= 0 {
		months = 12
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT date_trunc('month', hour) AS bucket,
		        COALESCE(SUM(bytes_total), 0)
		   FROM traffic_hourly
		  WHERE user_id = $1
		    AND hour >= NOW() - ($2::int * INTERVAL '1 month')
		  GROUP BY bucket
		  ORDER BY bucket ASC`,
		uid,
		months,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*MonthlyStat, 0, months)
	for rows.Next() {
		item := &MonthlyStat{}
		if err := rows.Scan(&item.Month, &item.BytesTotal); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func (s *trafficService) QueryRuleStats(ctx context.Context, ruleID string, from, to time.Time) ([]*HourlyPoint, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	rid, err := uuid.Parse(strings.TrimSpace(ruleID))
	if err != nil {
		return nil, ErrInvalidRuleID
	}

	start := from.UTC()
	end := to.UTC()
	if start.IsZero() {
		start = time.Now().UTC().Add(-24 * time.Hour)
	}
	if end.IsZero() {
		end = time.Now().UTC()
	}
	if !end.After(start) {
		return nil, ErrInvalidTrafficInput
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT date_trunc('hour', hour) AS bucket,
		        COALESCE(SUM(bytes_total), 0)
		   FROM traffic_hourly
		  WHERE rule_id = $1
		    AND hour >= $2
		    AND hour < $3
		  GROUP BY bucket
		  ORDER BY bucket ASC`,
		rid,
		start,
		end,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	points := make([]*HourlyPoint, 0, 64)
	for rows.Next() {
		item := &HourlyPoint{}
		if err := rows.Scan(&item.Hour, &item.BytesTotal); err != nil {
			return nil, err
		}
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return points, nil
}

func (s *trafficService) AdminOverview(ctx context.Context) (*TrafficOverview, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	now := time.Now().UTC()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	overview := &TrafficOverview{
		Top10Users: make([]TopUserTraffic, 0, 10),
		Top10Rules: make([]TopRuleTraffic, 0, 10),
	}

	if err := s.pool.QueryRow(
		ctx,
		`SELECT COALESCE(SUM(bytes_total), 0)
		   FROM traffic_hourly
		  WHERE hour >= $1`,
		todayStart,
	).Scan(&overview.TodayTotal); err != nil {
		return nil, err
	}

	if err := s.pool.QueryRow(
		ctx,
		`SELECT COALESCE(SUM(bytes_total), 0)
		   FROM traffic_hourly
		  WHERE hour >= $1`,
		monthStart,
	).Scan(&overview.MonthTotal); err != nil {
		return nil, err
	}

	userRows, err := s.pool.Query(
		ctx,
		`SELECT id, username, traffic_used, traffic_quota
		   FROM users
		  ORDER BY traffic_used DESC
		  LIMIT 10`,
	)
	if err != nil {
		return nil, err
	}
	for userRows.Next() {
		var userID uuid.UUID
		item := TopUserTraffic{}
		if err := userRows.Scan(&userID, &item.Username, &item.TrafficUsed, &item.TrafficQuota); err != nil {
			userRows.Close()
			return nil, err
		}
		item.UserID = userID.String()
		overview.Top10Users = append(overview.Top10Users, item)
	}
	if err := userRows.Err(); err != nil {
		userRows.Close()
		return nil, err
	}
	userRows.Close()

	ruleRows, err := s.pool.Query(
		ctx,
		`SELECT fr.id, fr.name, fr.owner_id, COALESCE(SUM(th.bytes_total), 0) AS total
		   FROM forwarding_rules fr
		   LEFT JOIN traffic_hourly th
		     ON th.rule_id = fr.id
		    AND th.hour >= $1
		  GROUP BY fr.id, fr.name, fr.owner_id
		  ORDER BY total DESC
		  LIMIT 10`,
		monthStart,
	)
	if err != nil {
		return nil, err
	}
	for ruleRows.Next() {
		var ruleID uuid.UUID
		var ownerID uuid.UUID
		item := TopRuleTraffic{}
		if err := ruleRows.Scan(&ruleID, &item.RuleName, &ownerID, &item.BytesTotal); err != nil {
			ruleRows.Close()
			return nil, err
		}
		item.RuleID = ruleID.String()
		item.OwnerID = ownerID.String()
		overview.Top10Rules = append(overview.Top10Rules, item)
	}
	if err := ruleRows.Err(); err != nil {
		ruleRows.Close()
		return nil, err
	}
	ruleRows.Close()

	return overview, nil
}

func (s *trafficService) ResetUserQuota(ctx context.Context, userID string) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return ErrInvalidUserID
	}

	tag, err := s.pool.Exec(ctx, `UPDATE users SET traffic_used = 0, updated_at = NOW() WHERE id = $1`, uid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	if s.auditRepo != nil {
		resourceID := uid.String()
		_ = s.auditRepo.Create(ctx, &model.AuditLog{
			UserID:       &uid,
			Action:       "user.quota.reset",
			ResourceType: strPtr("user"),
			ResourceID:   &resourceID,
			NewValue: map[string]interface{}{
				"traffic_used": 0,
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	return nil
}

func (s *trafficService) ResetAllMonthlyQuotas(ctx context.Context) (int64, error) {
	if s.pool == nil {
		return 0, errors.New("database pool is nil")
	}

	tag, err := s.pool.Exec(
		ctx,
		`UPDATE users
		    SET traffic_used = 0,
		        updated_at = NOW()
		  WHERE traffic_used <> 0`,
	)
	if err != nil {
		return 0, err
	}

	affected := tag.RowsAffected()
	if s.auditRepo != nil {
		_ = s.auditRepo.Create(ctx, &model.AuditLog{
			Action:       "user.quota.reset_monthly",
			ResourceType: strPtr("system"),
			NewValue: map[string]interface{}{
				"users_reset": affected,
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	return affected, nil
}

func (s *trafficService) BatchSyncQuota(ctx context.Context) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(
		ctx,
		`UPDATE users
		    SET traffic_used = 0,
		        updated_at = NOW()`,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		ctx,
		`UPDATE users u
		    SET traffic_used = agg.total,
		        updated_at = NOW()
		   FROM (
		       SELECT user_id, COALESCE(SUM(bytes_total), 0) AS total
		         FROM traffic_hourly
		        WHERE user_id IS NOT NULL
		        GROUP BY user_id
		   ) agg
		  WHERE u.id = agg.user_id`,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *trafficService) lookupBillingInfo(ctx context.Context, ruleID uuid.UUID) (*billingInfo, error) {
	query := `
		SELECT fr.owner_id,
		       fr.ingress_node_id,
		       COALESCE(na.traffic_ratio, 1.0) AS node_ratio,
		       COALESCE(vl.traffic_ratio, 1.0) AS vip_ratio
		  FROM forwarding_rules fr
		  JOIN users u ON u.id = fr.owner_id
		  LEFT JOIN node_agents na ON na.id = fr.ingress_node_id
		  LEFT JOIN vip_levels vl ON vl.level = u.vip_level
		 WHERE fr.id = $1
	`

	info := &billingInfo{}
	if err := s.pool.QueryRow(ctx, query, ruleID).Scan(
		&info.OwnerID,
		&info.IngressNodeID,
		&info.NodeRatio,
		&info.VIPRatio,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}

	if info.NodeRatio <= 0 {
		info.NodeRatio = 1.0
	}
	if info.VIPRatio <= 0 {
		info.VIPRatio = 1.0
	}

	return info, nil
}

func (s *trafficService) incrementUserTrafficUsed(ctx context.Context, userID uuid.UUID, delta int64) (int64, int64, error) {
	var used int64
	var quota int64
	err := s.pool.QueryRow(
		ctx,
		`UPDATE users
		    SET traffic_used = traffic_used + $1,
		        updated_at = NOW()
		  WHERE id = $2
		RETURNING traffic_used, traffic_quota`,
		delta,
		userID,
	).Scan(&used, &quota)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrUserNotFound
		}
		return 0, 0, err
	}

	return used, quota, nil
}

func (s *trafficService) pushHourlyRecord(record hourlyUpsertRecord) {
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()
	s.mergeHourlyRecord(s.primaryBuffer, record)
}

func (s *trafficService) batchWorker() {
	ticker := time.NewTicker(trafficFlushInterval)
	defer ticker.Stop()

	flush := func(ctx context.Context) {
		batch := s.swapBuffersForFlush()
		if len(batch) == 0 {
			return
		}

		if err := s.flushBatch(ctx, batch); err != nil {
			s.logger.Warn("flush traffic batch failed", zap.Error(err), zap.Int("rows", len(batch)))
			s.requeueBatch(batch)
			return
		}

		clear(batch)
	}

	for {
		select {
		case <-s.stopCh:
			flush(context.Background())
			return
		case <-ticker.C:
			flush(context.Background())
		}
	}
}

func (s *trafficService) flushBatch(ctx context.Context, batch map[hourlyUpsertKey]hourlyUpsertRecord) error {
	start := time.Now()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE IF NOT EXISTS tmp_traffic_hourly_batch (
			rule_id UUID NOT NULL,
			user_id UUID,
			hour TIMESTAMPTZ NOT NULL,
			bytes_in BIGINT NOT NULL,
			bytes_out BIGINT NOT NULL,
			bytes_total BIGINT NOT NULL,
			ratio_applied NUMERIC(5,2) NOT NULL
		) ON COMMIT DROP
	`); err != nil {
		return err
	}

	rows := make([][]any, 0, len(batch))
	for _, rec := range batch {
		userID := rec.UserID
		rows = append(rows, []any{
			rec.RuleID,
			userID,
			rec.Hour,
			rec.BytesIn,
			rec.BytesOut,
			rec.BytesTotal,
			rec.RatioApplied,
		})
	}

	copiedRows, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"tmp_traffic_hourly_batch"},
		[]string{"rule_id", "user_id", "hour", "bytes_in", "bytes_out", "bytes_total", "ratio_applied"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO traffic_hourly (
			rule_id,
			user_id,
			hour,
			bytes_in,
			bytes_out,
			bytes_total,
			ratio_applied
		)
		SELECT
			rule_id,
			MAX(user_id) AS user_id,
			hour,
			SUM(bytes_in) AS bytes_in,
			SUM(bytes_out) AS bytes_out,
			SUM(bytes_total) AS bytes_total,
			MAX(ratio_applied) AS ratio_applied
		FROM tmp_traffic_hourly_batch
		GROUP BY rule_id, hour
		ON CONFLICT (rule_id, hour)
		DO UPDATE SET
			user_id = COALESCE(EXCLUDED.user_id, traffic_hourly.user_id),
			bytes_in = traffic_hourly.bytes_in + EXCLUDED.bytes_in,
			bytes_out = traffic_hourly.bytes_out + EXCLUDED.bytes_out,
			bytes_total = traffic_hourly.bytes_total + EXCLUDED.bytes_total,
			ratio_applied = EXCLUDED.ratio_applied
	`); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	s.logger.Info("traffic batch flushed",
		zap.Int("rows", len(batch)),
		zap.Int64("copy_rows", copiedRows),
		zap.Duration("elapsed", time.Since(start)),
	)

	return nil
}

func (s *trafficService) swapBuffersForFlush() map[hourlyUpsertKey]hourlyUpsertRecord {
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()

	if len(s.primaryBuffer) == 0 {
		return nil
	}

	s.primaryBuffer, s.secondaryBuffer = s.secondaryBuffer, s.primaryBuffer
	if len(s.primaryBuffer) > 0 {
		clear(s.primaryBuffer)
	}

	return s.secondaryBuffer
}

func (s *trafficService) requeueBatch(batch map[hourlyUpsertKey]hourlyUpsertRecord) {
	if len(batch) == 0 {
		return
	}

	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()

	for _, rec := range batch {
		s.mergeHourlyRecord(s.primaryBuffer, rec)
	}
	clear(batch)
}

func (s *trafficService) mergeHourlyRecord(
	target map[hourlyUpsertKey]hourlyUpsertRecord,
	record hourlyUpsertRecord,
) {
	if target == nil {
		return
	}

	key := hourlyUpsertKey{
		RuleID: record.RuleID,
		Hour:   record.Hour,
	}
	if existing, ok := target[key]; ok {
		existing.BytesIn += record.BytesIn
		existing.BytesOut += record.BytesOut
		existing.BytesTotal += record.BytesTotal
		existing.RatioApplied = record.RatioApplied
		target[key] = existing
		return
	}

	target[key] = record
}
