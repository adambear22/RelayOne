package model

import (
	"time"

	"github.com/google/uuid"
)

type BenefitCode struct {
	ID           uuid.UUID  `db:"id" json:"id"`
	Code         string     `db:"code" json:"code"`
	VIPLevel     int        `db:"vip_level" json:"vip_level"`
	DurationDays int        `db:"duration_days" json:"duration_days"`
	ExpiresAt    *time.Time `db:"expires_at" json:"expires_at,omitempty"`
	ValidDays    int        `db:"valid_days" json:"valid_days"`
	IsUsed       bool       `db:"is_used" json:"is_used"`
	IsEnabled    bool       `db:"is_enabled" json:"is_enabled"`
	UsedBy       *uuid.UUID `db:"used_by" json:"used_by,omitempty"`
	UsedAt       *time.Time `db:"used_at" json:"used_at,omitempty"`
	CreatedBy    uuid.UUID  `db:"created_by" json:"created_by"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
}
