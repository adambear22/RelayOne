package model

import "time"

type VIPLevel struct {
	Level               int                    `db:"level" json:"level"`
	Name                string                 `db:"name" json:"name"`
	TrafficQuota        int64                  `db:"traffic_quota" json:"traffic_quota"`
	MaxRules            int                    `db:"max_rules" json:"max_rules"`
	BandwidthLimit      int64                  `db:"bandwidth_limit" json:"bandwidth_limit"`
	MaxIngressNodes     int                    `db:"max_ingress_nodes" json:"max_ingress_nodes"`
	MaxEgressNodes      int                    `db:"max_egress_nodes" json:"max_egress_nodes"`
	AccessibleNodeLevel int                    `db:"accessible_node_level" json:"accessible_node_level"`
	TrafficRatio        float64                `db:"traffic_ratio" json:"traffic_ratio"`
	CustomFeatures      map[string]interface{} `db:"custom_features" json:"custom_features,omitempty"`
	CreatedAt           time.Time              `db:"created_at" json:"created_at"`
}
