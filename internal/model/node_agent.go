package model

import (
	"time"

	"github.com/google/uuid"
)

type NodeAgent struct {
	ID                     uuid.UUID              `db:"id" json:"id"`
	Name                   string                 `db:"name" json:"name"`
	Type                   string                 `db:"type" json:"type"`
	OwnerID                *uuid.UUID             `db:"owner_id" json:"owner_id,omitempty"`
	IsSelfHosted           bool                   `db:"is_self_hosted" json:"is_self_hosted"`
	Host                   string                 `db:"host" json:"host"`
	APIPort                int                    `db:"api_port" json:"api_port"`
	Token                  string                 `db:"token" json:"token"`
	Status                 string                 `db:"status" json:"status"`
	DeployStatus           string                 `db:"deploy_status" json:"deploy_status"`
	DeployError            *string                `db:"deploy_error" json:"deploy_error,omitempty"`
	VIPLevelReq            int                    `db:"vip_level_req" json:"vip_level_req"`
	TrafficRatio           float64                `db:"traffic_ratio" json:"traffic_ratio"`
	PortRangeMin           *int                   `db:"port_range_min" json:"port_range_min,omitempty"`
	PortRangeMax           *int                   `db:"port_range_max" json:"port_range_max,omitempty"`
	Arch                   string                 `db:"arch" json:"arch"`
	AgentVersion           *string                `db:"agent_version" json:"agent_version,omitempty"`
	SysInfo                map[string]interface{} `db:"sys_info" json:"sys_info,omitempty"`
	LastSeenAt             *time.Time             `db:"last_seen_at" json:"last_seen_at,omitempty"`
	InstallScriptExpiresAt *time.Time             `db:"install_script_expires_at" json:"install_script_expires_at,omitempty"`
	CreatedAt              time.Time              `db:"created_at" json:"created_at"`
}
