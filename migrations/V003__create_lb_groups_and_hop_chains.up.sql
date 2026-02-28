CREATE TABLE lb_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL,
    owner_id UUID REFERENCES users(id),
    strategy VARCHAR(20) NOT NULL DEFAULT 'round_robin',
    health_check_interval INTEGER NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE lb_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES lb_groups(id) ON DELETE CASCADE,
    node_id UUID NOT NULL REFERENCES node_agents(id),
    weight INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, node_id)
);

CREATE TABLE hop_chains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL,
    owner_id UUID REFERENCES users(id),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE hop_chain_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id UUID NOT NULL REFERENCES hop_chains(id) ON DELETE CASCADE,
    hop_order INTEGER NOT NULL,
    node_id UUID NOT NULL REFERENCES node_agents(id),
    np_params_override JSONB,
    UNIQUE (chain_id, hop_order)
);
