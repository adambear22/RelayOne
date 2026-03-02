package jobs

import (
	"context"
	"time"

	"go.uber.org/zap"

	"nodepass-hub/internal/service"
)

type PolicyJob struct {
	policyService *service.PolicyService
	logger        *zap.Logger
}

func NewPolicyJob(policyService *service.PolicyService, logger *zap.Logger) *PolicyJob {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &PolicyJob{
		policyService: policyService,
		logger:        logger,
	}
}

func (j *PolicyJob) PauseOverlimit() {
	if j == nil || j.policyService == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	paused, err := j.policyService.PauseOverlimitUsers(ctx)
	if err != nil {
		j.logger.Warn("pause overlimit users failed", zap.Error(err))
	}

	if len(paused) > 0 {
		j.logger.Info("pause overlimit users finished",
			zap.Int("paused_users", len(paused)),
			zap.Strings("user_ids", uuidListToStrings(paused)),
		)
	}
}
