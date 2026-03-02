package jobs

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/service"
)

type ruleSyncer interface {
	SyncRule(ctx context.Context, ruleID string) error
}

type RuleJob struct {
	pool                *pgxpool.Pool
	ruleService         ruleSyncer
	notificationService *service.NotificationService
	logger              *zap.Logger
	failures            sync.Map
}

func NewRuleJob(
	pool *pgxpool.Pool,
	ruleService ruleSyncer,
	notificationService *service.NotificationService,
	logger *zap.Logger,
) *RuleJob {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &RuleJob{
		pool:                pool,
		ruleService:         ruleService,
		notificationService: notificationService,
		logger:              logger,
	}
}

func (j *RuleJob) CleanDeadInstances() {
	if j == nil || j.pool == nil || j.ruleService == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rows, err := j.pool.Query(
		ctx,
		`SELECT id
		   FROM forwarding_rules
		  WHERE sync_status = 'sync_failed'
		    AND updated_at < NOW() - INTERVAL '1 hour'`,
	)
	if err != nil {
		j.logger.Warn("query dead rule instances failed", zap.Error(err))
		return
	}
	defer rows.Close()

	retried := 0
	for rows.Next() {
		var ruleID uuid.UUID
		if err := rows.Scan(&ruleID); err != nil {
			j.logger.Warn("scan dead rule failed", zap.Error(err))
			continue
		}

		retried++
		if err := j.ruleService.SyncRule(ctx, ruleID.String()); err != nil {
			attempt := j.recordFailure(ruleID.String())
			j.logger.Warn("retry dead rule instance failed",
				zap.String("rule_id", ruleID.String()),
				zap.Int("attempt", attempt),
				zap.Error(err),
			)

			if attempt >= 3 {
				j.notifyRuleSyncFailure(ruleID.String(), err.Error())
			}
			continue
		}

		j.clearFailure(ruleID.String())
	}

	if err := rows.Err(); err != nil {
		j.logger.Warn("iterate dead rules failed", zap.Error(err))
		return
	}

	if retried > 0 {
		j.logger.Info("rule dead instance cleanup finished", zap.Int("retried_rules", retried))
	}
}

func (j *RuleJob) recordFailure(ruleID string) int {
	raw, _ := j.failures.LoadOrStore(ruleID, 0)
	current, _ := raw.(int)
	current++
	j.failures.Store(ruleID, current)
	return current
}

func (j *RuleJob) clearFailure(ruleID string) {
	j.failures.Delete(ruleID)
}

func (j *RuleJob) notifyRuleSyncFailure(ruleID, reason string) {
	if j.notificationService == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := j.notificationService.SendToAdmins(ctx, service.NotificationRuleSyncFail, map[string]string{
		"rule_id": ruleID,
		"reason":  reason,
	}); err != nil {
		j.logger.Warn("send rule sync failed notification failed",
			zap.String("rule_id", ruleID),
			zap.Error(err),
		)
	}
}
