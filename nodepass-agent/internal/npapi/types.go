package npapi

type MasterInfo struct {
	Version string `json:"version"`
	Uptime  int64  `json:"uptime,omitempty"`
}

type Instance struct {
	ID                string `json:"id"`
	RuleID            string `json:"rule_id,omitempty"`
	URL               string `json:"url,omitempty"`
	Status            string `json:"status,omitempty"`
	ActiveConnections int    `json:"active_connections,omitempty"`
	BytesIn           int64  `json:"bytes_in,omitempty"`
	BytesOut          int64  `json:"bytes_out,omitempty"`
}

type CreateInstanceRequest struct {
	URL string `json:"url"`
}

type UpdateInstanceRequest struct {
	URL string `json:"url,omitempty"`
}
