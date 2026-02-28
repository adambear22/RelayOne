package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"nodepass-hub/internal/model"
)

type Pagination struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

type UserListFilter struct {
	Role       *model.UserRole   `json:"role,omitempty"`
	Status     *model.UserStatus `json:"status,omitempty"`
	Keyword    *string           `json:"keyword,omitempty"`
	Pagination Pagination        `json:"pagination"`
}

type NodeListFilter struct {
	OwnerID      *uuid.UUID `json:"owner_id,omitempty"`
	Type         *string    `json:"type,omitempty"`
	Status       *string    `json:"status,omitempty"`
	DeployStatus *string    `json:"deploy_status,omitempty"`
	Pagination   Pagination `json:"pagination"`
}

type RuleListFilter struct {
	OwnerID    *uuid.UUID `json:"owner_id,omitempty"`
	NodeID     *uuid.UUID `json:"node_id,omitempty"`
	Mode       *string    `json:"mode,omitempty"`
	Status     *string    `json:"status,omitempty"`
	SyncStatus *string    `json:"sync_status,omitempty"`
	Pagination Pagination `json:"pagination"`
}

type TrafficPeriod string

const (
	TrafficPeriodDay   TrafficPeriod = "day"
	TrafficPeriodMonth TrafficPeriod = "month"
)

type AuditListFilter struct {
	UserID       *uuid.UUID `json:"user_id,omitempty"`
	ResourceType *string    `json:"resource_type,omitempty"`
	StartTime    *time.Time `json:"start_time,omitempty"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	Pagination   Pagination `json:"pagination"`
}

type UserRepository interface {
	FindByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	FindByUsername(ctx context.Context, username string) (*model.User, error)
	FindByTelegramID(ctx context.Context, telegramID int64) (*model.User, error)
	Create(ctx context.Context, user *model.User) error
	Update(ctx context.Context, user *model.User) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status model.UserStatus) error
	UpdateTrafficUsed(ctx context.Context, id uuid.UUID, delta int64) error
	List(ctx context.Context, filter UserListFilter) ([]*model.User, error)
	Count(ctx context.Context, filter UserListFilter) (int64, error)
}

type NodeRepository interface {
	FindByID(ctx context.Context, id uuid.UUID) (*model.NodeAgent, error)
	FindByOwner(ctx context.Context, ownerID uuid.UUID, page Pagination) ([]*model.NodeAgent, error)
	Create(ctx context.Context, node *model.NodeAgent) error
	Update(ctx context.Context, node *model.NodeAgent) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateDeployStatus(ctx context.Context, id uuid.UUID, deployStatus string, deployError *string) error
	List(ctx context.Context, filter NodeListFilter) ([]*model.NodeAgent, error)
}

type RuleRepository interface {
	FindByID(ctx context.Context, id uuid.UUID) (*model.ForwardingRule, error)
	FindByOwner(ctx context.Context, ownerID uuid.UUID, page Pagination) ([]*model.ForwardingRule, error)
	Create(ctx context.Context, rule *model.ForwardingRule) error
	Update(ctx context.Context, rule *model.ForwardingRule) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateSyncStatus(ctx context.Context, id uuid.UUID, syncStatus string) error
	Delete(ctx context.Context, id uuid.UUID) error
	BatchDelete(ctx context.Context, ids []uuid.UUID) error
	List(ctx context.Context, filter RuleListFilter) ([]*model.ForwardingRule, error)
}

type TrafficRepository interface {
	Upsert(ctx context.Context, traffic *model.TrafficHourly) error
	SumByUser(ctx context.Context, userID uuid.UUID, period TrafficPeriod, referenceTime time.Time) (int64, error)
	SumByRule(ctx context.Context, ruleID uuid.UUID, start, end time.Time) (int64, error)
}

type BenefitCodeRepository interface {
	FindByCode(ctx context.Context, code string) (*model.BenefitCode, error)
	Create(ctx context.Context, benefitCode *model.BenefitCode) error
	BatchCreate(ctx context.Context, benefitCodes []*model.BenefitCode) error
	Update(ctx context.Context, benefitCode *model.BenefitCode) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type AuditRepository interface {
	Create(ctx context.Context, log *model.AuditLog) error
	List(ctx context.Context, filter AuditListFilter) ([]*model.AuditLog, error)
}
