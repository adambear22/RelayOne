package model

import (
	"time"

	"github.com/google/uuid"
)

type LBGroup struct {
	ID                  uuid.UUID  `db:"id" json:"id"`
	Name                string     `db:"name" json:"name"`
	OwnerID             *uuid.UUID `db:"owner_id" json:"owner_id,omitempty"`
	Strategy            string     `db:"strategy" json:"strategy"`
	HealthCheckInterval int        `db:"health_check_interval" json:"health_check_interval"`
	CreatedAt           time.Time  `db:"created_at" json:"created_at"`
}

type LBGroupMember struct {
	ID        uuid.UUID `db:"id" json:"id"`
	GroupID   uuid.UUID `db:"group_id" json:"group_id"`
	NodeID    uuid.UUID `db:"node_id" json:"node_id"`
	Weight    int       `db:"weight" json:"weight"`
	IsActive  bool      `db:"is_active" json:"is_active"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
