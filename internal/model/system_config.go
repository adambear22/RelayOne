package model

import "time"

type TelegramConfig struct {
	BotToken      string `json:"bot_token,omitempty"`
	BotUsername   string `json:"bot_username,omitempty"`
	WebhookURL    string `json:"webhook_url,omitempty"`
	WebhookSecret string `json:"webhook_secret,omitempty"`
	FrontendURL   string `json:"frontend_url,omitempty"`
	SSOBaseURL    string `json:"sso_base_url,omitempty"`
	DefaultChatID int64  `json:"default_chat_id,omitempty"`
	Enabled       bool   `json:"enabled,omitempty"`
}

type ExternalAPIKey struct {
	Name   string   `json:"name"`
	Key    string   `json:"key,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

type SystemConfig struct {
	ID                  int              `db:"id" json:"id"`
	SiteName            *string          `db:"site_name" json:"site_name,omitempty"`
	SupportEmail        *string          `db:"support_email" json:"support_email,omitempty"`
	MaintenanceMode     bool             `db:"maintenance_mode" json:"maintenance_mode"`
	RegistrationEnabled bool             `db:"registration_enabled" json:"registration_enabled"`
	DefaultTrafficQuota int64            `db:"default_traffic_quota" json:"default_traffic_quota"`
	DefaultMaxRules     int              `db:"default_max_rules" json:"default_max_rules"`
	TelegramConfig      TelegramConfig   `db:"telegram_config" json:"telegram_config"`
	ExternalAPIKeys     []ExternalAPIKey `db:"external_api_keys" json:"-"`
	UpdatedAt           time.Time        `db:"updated_at" json:"updated_at"`
}
