package jobs

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"nodepass-hub/internal/service"
)

type TrafficJob struct {
	trafficService      service.TrafficService
	policyService       *service.PolicyService
	notificationService *service.NotificationService
	logger              *zap.Logger
}

func NewTrafficJob(
	trafficService service.TrafficService,
	policyService *service.PolicyService,
	notificationService *service.NotificationService,
	logger *zap.Logger,
) *TrafficJob {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &TrafficJob{
		trafficService:      trafficService,
		policyService:       policyService,
		notificationService: notificationService,
		logger:              logger,
	}
}

func (j *TrafficJob) ResetMonthlyQuotas() {
	if j == nil || j.trafficService == nil {
		return
	}

	start := time.Now()

	var (
		affected int64
		resumed  []uuid.UUID
		lastErr  error
	)

	backoff := time.Second
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		affected, lastErr = j.trafficService.ResetAllMonthlyQuotas(ctx)
		if lastErr == nil && j.policyService != nil {
			resumed, lastErr = j.policyService.ResumeAllOverlimitUsers(ctx)
		}
		cancel()

		if lastErr == nil {
			j.logger.Info("monthly traffic quotas reset finished",
				zap.Int64("users_reset", affected),
				zap.Int("resumed_users", len(resumed)),
				zap.Strings("resumed_user_ids", uuidListToStrings(resumed)),
				zap.Duration("cost", time.Since(start)),
			)
			return
		}

		if attempt < 3 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	j.logger.Error("monthly traffic quota reset failed",
		zap.Error(lastErr),
		zap.Duration("cost", time.Since(start)),
	)
	j.notifyFailure("job.traffic_reset", lastErr)
}

func (j *TrafficJob) SyncBatch() {
	if j == nil || j.trafficService == nil {
		return
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := j.trafficService.BatchSyncQuota(ctx); err != nil {
		j.logger.Warn("traffic sync batch failed", zap.Error(err))
		return
	}

	j.logger.Info("traffic sync batch finished", zap.Duration("cost", time.Since(start)))
}

func (j *TrafficJob) notifyFailure(subject string, err error) {
	if err == nil || j == nil || j.notificationService == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if notifyErr := j.notificationService.SendToAdmins(ctx, service.NotificationRuleSyncFail, map[string]string{
		"rule_id": subject,
		"reason":  err.Error(),
	}); notifyErr != nil {
		j.logger.Warn("send scheduler failure notification failed",
			zap.String("subject", subject),
			zap.Error(notifyErr),
		)
	}
}
