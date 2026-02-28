package model

import (
	"time"

	"github.com/google/uuid"
)

type AuditLog struct {
	ID           int64                  `db:"id" json:"id"`
	UserID       *uuid.UUID             `db:"user_id" json:"user_id,omitempty"`
	Action       string                 `db:"action" json:"action"`
	ResourceType *string                `db:"resource_type" json:"resource_type,omitempty"`
	ResourceID   *string                `db:"resource_id" json:"resource_id,omitempty"`
	OldValue     map[string]interface{} `db:"old_value" json:"old_value,omitempty"`
	NewValue     map[string]interface{} `db:"new_value" json:"new_value,omitempty"`
	IPAddress    *string                `db:"ip_address" json:"ip_address,omitempty"`
	UserAgent    *string                `db:"user_agent" json:"user_agent,omitempty"`
	CreatedAt    time.Time              `db:"created_at" json:"created_at"`
}
