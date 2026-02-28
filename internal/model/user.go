package model

import (
	"time"

	"github.com/google/uuid"
)

type UserStatus string

type UserRole string

const (
	UserStatusNormal    UserStatus = "normal"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusBanned    UserStatus = "banned"
	UserStatusOverLimit UserStatus = "over_limit"
)

const (
	UserRoleUser  UserRole = "user"
	UserRoleAdmin UserRole = "admin"
)

type User struct {
	ID               uuid.UUID  `db:"id" json:"id"`
	Username         string     `db:"username" json:"username"`
	PasswordHash     string     `db:"password_hash" json:"-"`
	Email            *string    `db:"email" json:"email,omitempty"`
	Role             UserRole   `db:"role" json:"role"`
	Status           UserStatus `db:"status" json:"status"`
	TelegramID       *int64     `db:"telegram_id" json:"telegram_id,omitempty"`
	TelegramUsername *string    `db:"telegram_username" json:"telegram_username,omitempty"`
	VIPLevel         int        `db:"vip_level" json:"vip_level"`
	VIPExpiresAt     *time.Time `db:"vip_expires_at" json:"vip_expires_at,omitempty"`
	TrafficQuota     int64      `db:"traffic_quota" json:"traffic_quota"`
	TrafficUsed      int64      `db:"traffic_used" json:"traffic_used"`
	BandwidthLimit   int64      `db:"bandwidth_limit" json:"bandwidth_limit"`
	MaxRules         int        `db:"max_rules" json:"max_rules"`
	Permissions      []string   `db:"permissions" json:"permissions,omitempty"`
	CreatedAt        time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt        time.Time  `db:"updated_at" json:"updated_at"`
}
