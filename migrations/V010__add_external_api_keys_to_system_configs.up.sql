ALTER TABLE system_configs
    ADD COLUMN IF NOT EXISTS external_api_keys JSONB NOT NULL DEFAULT '[]'::jsonb;
