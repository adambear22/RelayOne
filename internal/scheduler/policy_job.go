package scheduler

import (
	"context"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"

	"nodepass-hub/internal/service"
)

const policySchedule = "@every 5m"

type PolicyJob struct {
	cron          *cron.Cron
	policyService *service.PolicyService
	logger        *zap.Logger
}

func NewPolicyJob(policyService *service.PolicyService, logger *zap.Logger) *PolicyJob {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &PolicyJob{
		cron:          cron.New(cron.WithLocation(time.UTC)),
		policyService: policyService,
		logger:        logger,
	}
}

func (j *PolicyJob) Start() error {
	if j == nil || j.cron == nil || j.policyService == nil {
		return nil
	}

	_, err := j.cron.AddFunc(policySchedule, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if err := j.policyService.BatchPauseOverlimitUsers(ctx); err != nil {
			j.logger.Warn("policy batch pause job failed", zap.Error(err))
		}
	})
	if err != nil {
		return err
	}

	j.cron.Start()
	return nil
}

func (j *PolicyJob) Stop() {
	if j == nil || j.cron == nil {
		return
	}

	stopCtx := j.cron.Stop()
	select {
	case <-stopCtx.Done():
	case <-time.After(2 * time.Second):
	}
}
