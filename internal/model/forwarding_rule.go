package model

import (
	"time"

	"github.com/google/uuid"
)

type NpParams struct {
	NpTLS   *int    `db:"np_tls" json:"np_tls,omitempty"`
	NpMode  *string `db:"np_mode" json:"np_mode,omitempty"`
	NpMin   *int    `db:"np_min" json:"np_min,omitempty"`
	NpMax   *int    `db:"np_max" json:"np_max,omitempty"`
	NpRate  *int    `db:"np_rate" json:"np_rate,omitempty"`
	NpNoTCP *bool   `db:"np_notcp" json:"np_notcp,omitempty"`
	NpNoUDP *bool   `db:"np_noudp" json:"np_noudp,omitempty"`
	NpLog   *string `db:"np_log" json:"np_log,omitempty"`
}

type ForwardingRule struct {
	ID            uuid.UUID              `db:"id" json:"id"`
	Name          string                 `db:"name" json:"name"`
	OwnerID       uuid.UUID              `db:"owner_id" json:"owner_id"`
	Mode          string                 `db:"mode" json:"mode"`
	IngressNodeID uuid.UUID              `db:"ingress_node_id" json:"ingress_node_id"`
	IngressPort   int                    `db:"ingress_port" json:"ingress_port"`
	EgressNodeID  *uuid.UUID             `db:"egress_node_id" json:"egress_node_id,omitempty"`
	LBGroupID     *uuid.UUID             `db:"lb_group_id" json:"lb_group_id,omitempty"`
	HopChainID    *uuid.UUID             `db:"hop_chain_id" json:"hop_chain_id,omitempty"`
	TargetHost    string                 `db:"target_host" json:"target_host"`
	TargetPort    int                    `db:"target_port" json:"target_port"`
	Status        string                 `db:"status" json:"status"`
	SyncStatus    string                 `db:"sync_status" json:"sync_status"`
	InstanceInfo  map[string]interface{} `db:"instance_info" json:"instance_info,omitempty"`
	NpParams      NpParams               `db:"-" json:"np_params"`
	CreatedAt     time.Time              `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time              `db:"updated_at" json:"updated_at"`
}
