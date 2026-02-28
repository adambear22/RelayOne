package model

import (
	"time"

	"github.com/google/uuid"
)

type TrafficHourly struct {
	ID           int64      `db:"id" json:"id"`
	RuleID       uuid.UUID  `db:"rule_id" json:"rule_id"`
	UserID       *uuid.UUID `db:"user_id" json:"user_id,omitempty"`
	Hour         time.Time  `db:"hour" json:"hour"`
	BytesIn      int64      `db:"bytes_in" json:"bytes_in"`
	BytesOut     int64      `db:"bytes_out" json:"bytes_out"`
	BytesTotal   int64      `db:"bytes_total" json:"bytes_total"`
	RatioApplied float64    `db:"ratio_applied" json:"ratio_applied"`
}
