package scheduler

import (
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

const (
	specTrafficReset = "0 0 0 1 * *"
	specVIPCheck     = "0 0 0 * * *"
	specPolicyPause  = "0 */5 * * * *"
	specTrafficSync  = "0 */10 * * * *"
	specNodeCheck    = "*/30 * * * * *"
	specRuleClean    = "0 0 * * * *"
)

type TrafficTask interface {
	ResetMonthlyQuotas()
	SyncBatch()
}

type VIPTask interface {
	CheckExpiry()
}

type PolicyTask interface {
	PauseOverlimit()
}

type NodeTask interface {
	CheckHeartbeats()
}

type RuleTask interface {
	CleanDeadInstances()
}

type Deps struct {
	TrafficJob TrafficTask
	VIPJob     VIPTask
	PolicyJob  PolicyTask
	NodeJob    NodeTask
	RuleJob    RuleTask
}

func NewScheduler(deps Deps, logger *zap.Logger) *cron.Cron {
	if logger == nil {
		logger = zap.NewNop()
	}

	c := cron.New(cron.WithSeconds(), cron.WithLocation(time.UTC))

	if deps.TrafficJob != nil {
		addFunc(c, specTrafficReset, "traffic.reset_monthly", logger, deps.TrafficJob.ResetMonthlyQuotas)
		addFunc(c, specTrafficSync, "traffic.sync_batch", logger, deps.TrafficJob.SyncBatch)
	}
	if deps.VIPJob != nil {
		addFunc(c, specVIPCheck, "vip.check_expiry", logger, deps.VIPJob.CheckExpiry)
	}
	if deps.PolicyJob != nil {
		addFunc(c, specPolicyPause, "policy.pause_overlimit", logger, deps.PolicyJob.PauseOverlimit)
	}
	if deps.NodeJob != nil {
		addFunc(c, specNodeCheck, "node.check_heartbeats", logger, deps.NodeJob.CheckHeartbeats)
	}
	if deps.RuleJob != nil {
		addFunc(c, specRuleClean, "rule.clean_dead_instances", logger, deps.RuleJob.CleanDeadInstances)
	}

	return c
}

func addFunc(c *cron.Cron, spec string, name string, logger *zap.Logger, fn func()) {
	if c == nil || fn == nil {
		return
	}

	if _, err := c.AddFunc(spec, func() {
		defer recoverJobPanic(name, logger)
		start := time.Now()
		fn()
		logger.Debug("scheduler job finished", zap.String("job", name), zap.Duration("cost", time.Since(start)))
	}); err != nil {
		logger.Error("register scheduler job failed",
			zap.String("job", name),
			zap.String("spec", spec),
			zap.Error(err),
		)
	}
}

func recoverJobPanic(jobName string, logger *zap.Logger) {
	if logger == nil {
		return
	}

	if recovered := recover(); recovered != nil {
		logger.Error("scheduler job panic recovered",
			zap.String("job", jobName),
			zap.Any("panic", recovered),
		)
	}
}
