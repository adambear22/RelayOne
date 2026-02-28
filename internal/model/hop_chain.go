package model

import (
	"time"

	"github.com/google/uuid"
)

type HopChain struct {
	ID          uuid.UUID  `db:"id" json:"id"`
	Name        string     `db:"name" json:"name"`
	OwnerID     *uuid.UUID `db:"owner_id" json:"owner_id,omitempty"`
	Description *string    `db:"description" json:"description,omitempty"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
}

type HopChainNode struct {
	ID               uuid.UUID              `db:"id" json:"id"`
	ChainID          uuid.UUID              `db:"chain_id" json:"chain_id"`
	HopOrder         int                    `db:"hop_order" json:"hop_order"`
	NodeID           uuid.UUID              `db:"node_id" json:"node_id"`
	NpParamsOverride map[string]interface{} `db:"np_params_override" json:"np_params_override,omitempty"`
}
