package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/model"
)

const (
	PolicyPauseRules  = "pause_rules"
	PolicyResumeRules = "resume_rules"
	PolicyResetQuota  = "reset_quota"
)

var (
	ErrInvalidPolicy = errors.New("invalid policy")
)

type PolicyService struct {
	pool           *pgxpool.Pool
	ruleService    *RuleService
	trafficService TrafficService
	logger         *zap.Logger
}

func NewPolicyService(
	pool *pgxpool.Pool,
	ruleService *RuleService,
	trafficService TrafficService,
	logger *zap.Logger,
) *PolicyService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &PolicyService{
		pool:           pool,
		ruleService:    ruleService,
		trafficService: trafficService,
		logger:         logger,
	}
}

func (s *PolicyService) EnforcePolicy(ctx context.Context, userID string, policy string) error {
	uid := strings.TrimSpace(userID)
	if _, err := uuid.Parse(uid); err != nil {
		return ErrInvalidUserID
	}

	switch strings.ToLower(strings.TrimSpace(policy)) {
	case PolicyPauseRules:
		if s.ruleService == nil {
			return errors.New("rule service is nil")
		}
		return s.ruleService.PauseAllUserRules(ctx, uid)
	case PolicyResumeRules:
		if s.ruleService == nil {
			return errors.New("rule service is nil")
		}
		return s.ruleService.ResumeAllUserRules(ctx, uid)
	case PolicyResetQuota:
		if s.trafficService == nil {
			return errors.New("traffic service is nil")
		}
		return s.trafficService.ResetUserQuota(ctx, uid)
	default:
		return ErrInvalidPolicy
	}
}

func (s *PolicyService) BatchPauseOverlimitUsers(ctx context.Context) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}
	if s.ruleService == nil {
		return errors.New("rule service is nil")
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT id
		   FROM users
		  WHERE status = $1
		    AND (
		      traffic_used >= traffic_quota
		      OR (vip_expires_at IS NOT NULL AND vip_expires_at < NOW())
		    )`,
		model.UserStatusNormal,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	var firstErr error
	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return err
		}

		if err := s.ruleService.PauseAllUserRules(ctx, userID.String()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.logger.Warn("batch pause overlimit user rules failed",
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	return firstErr
}
