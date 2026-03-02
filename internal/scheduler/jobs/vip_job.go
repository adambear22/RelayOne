package jobs

import (
	"context"
	"time"

	"go.uber.org/zap"

	"nodepass-hub/internal/service"
)

type VIPJob struct {
	vipService *service.VIPService
	logger     *zap.Logger
}

func NewVIPJob(vipService *service.VIPService, logger *zap.Logger) *VIPJob {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &VIPJob{
		vipService: vipService,
		logger:     logger,
	}
}

func (j *VIPJob) CheckExpiry() {
	if j == nil || j.vipService == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := j.vipService.CheckExpiry(ctx); err != nil {
		j.logger.Warn("vip expiry check failed", zap.Error(err))
	}
}
