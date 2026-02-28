package scheduler

import (
	"context"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"

	"nodepass-hub/internal/service"
)

const vipExpirySchedule = "@every 5m"

type VIPExpiryJob struct {
	cron       *cron.Cron
	vipService *service.VIPService
	logger     *zap.Logger
}

func NewVIPExpiryJob(vipService *service.VIPService, logger *zap.Logger) *VIPExpiryJob {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &VIPExpiryJob{
		cron:       cron.New(cron.WithLocation(time.UTC)),
		vipService: vipService,
		logger:     logger,
	}
}

func (j *VIPExpiryJob) Start() error {
	if j == nil || j.cron == nil || j.vipService == nil {
		return nil
	}

	_, err := j.cron.AddFunc(vipExpirySchedule, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if err := j.vipService.CheckExpiry(ctx); err != nil {
			j.logger.Warn("vip expiry check failed", zap.Error(err))
		}
	})
	if err != nil {
		return err
	}

	j.cron.Start()
	return nil
}

func (j *VIPExpiryJob) Stop() {
	if j == nil || j.cron == nil {
		return
	}

	stopCtx := j.cron.Stop()
	select {
	case <-stopCtx.Done():
	case <-time.After(2 * time.Second):
	}
}
