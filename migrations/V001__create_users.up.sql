CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    status VARCHAR(20) NOT NULL DEFAULT 'normal',
    telegram_id BIGINT UNIQUE,
    telegram_username VARCHAR(64),
    vip_level INTEGER NOT NULL DEFAULT 0,
    vip_expires_at TIMESTAMPTZ,
    traffic_quota BIGINT NOT NULL DEFAULT 0,
    traffic_used BIGINT NOT NULL DEFAULT 0,
    bandwidth_limit BIGINT NOT NULL DEFAULT 0,
    max_rules INTEGER NOT NULL DEFAULT 5,
    permissions TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
