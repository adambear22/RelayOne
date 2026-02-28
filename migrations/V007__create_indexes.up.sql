CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);
CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users (telegram_id);

CREATE INDEX IF NOT EXISTS idx_rules_owner_id ON forwarding_rules (owner_id);
CREATE INDEX IF NOT EXISTS idx_rules_status ON forwarding_rules (status);
CREATE INDEX IF NOT EXISTS idx_rules_lb_group ON forwarding_rules (lb_group_id);
CREATE INDEX IF NOT EXISTS idx_rules_hop_chain ON forwarding_rules (hop_chain_id);

CREATE INDEX IF NOT EXISTS idx_traffic_hourly_rule_hour ON traffic_hourly (rule_id, hour);
CREATE INDEX IF NOT EXISTS idx_traffic_hourly_user_hour ON traffic_hourly (user_id, hour);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON audit_logs (user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs (created_at);

CREATE INDEX IF NOT EXISTS idx_benefit_codes_code ON benefit_codes (code);

CREATE INDEX IF NOT EXISTS idx_node_deploy_logs_node ON node_deploy_logs (node_id);

CREATE INDEX IF NOT EXISTS idx_hop_chain_nodes_chain ON hop_chain_nodes (chain_id);

CREATE INDEX IF NOT EXISTS idx_node_agents_deploy_status
    ON node_agents (deploy_status)
    WHERE deploy_status <> 'success';
