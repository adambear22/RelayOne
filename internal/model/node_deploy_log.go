package model

import (
	"time"

	"github.com/google/uuid"
)

type NodeDeployLog struct {
	ID        int64     `db:"id" json:"id"`
	NodeID    uuid.UUID `db:"node_id" json:"node_id"`
	Step      string    `db:"step" json:"step"`
	Progress  int       `db:"progress" json:"progress"`
	Message   *string   `db:"message" json:"message,omitempty"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
