package model

import (
	"time"

	"github.com/google/uuid"
)

type Announcement struct {
	ID        uuid.UUID  `db:"id" json:"id"`
	Type      string     `db:"type" json:"type"`
	Title     string     `db:"title" json:"title"`
	Content   string     `db:"content" json:"content"`
	IsEnabled bool       `db:"is_enabled" json:"is_enabled"`
	StartsAt  *time.Time `db:"starts_at" json:"starts_at,omitempty"`
	EndsAt    *time.Time `db:"ends_at" json:"ends_at,omitempty"`
	CreatedBy uuid.UUID  `db:"created_by" json:"created_by"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}
