CREATE TABLE vip_levels (
    level INTEGER PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    traffic_quota BIGINT NOT NULL,
    max_rules INTEGER NOT NULL,
    bandwidth_limit BIGINT NOT NULL,
    max_ingress_nodes INTEGER DEFAULT 0,
    max_egress_nodes INTEGER DEFAULT 0,
    accessible_node_level INTEGER DEFAULT 0,
    traffic_ratio NUMERIC(5,2) DEFAULT 1.0,
    custom_features JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE traffic_hourly (
    id BIGSERIAL PRIMARY KEY,
    rule_id UUID NOT NULL REFERENCES forwarding_rules(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    hour TIMESTAMPTZ NOT NULL,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    bytes_total BIGINT DEFAULT 0,
    ratio_applied NUMERIC(5,2) DEFAULT 1.0,
    UNIQUE (rule_id, hour)
);

CREATE TABLE benefit_codes (
    id UUID PRIMARY KEY,
    code VARCHAR(64) UNIQUE NOT NULL,
    vip_level INTEGER NOT NULL REFERENCES vip_levels(level),
    duration_days INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ,
    valid_days INTEGER DEFAULT 30,
    is_used BOOLEAN DEFAULT FALSE,
    is_enabled BOOLEAN DEFAULT TRUE,
    used_by UUID REFERENCES users(id),
    used_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
