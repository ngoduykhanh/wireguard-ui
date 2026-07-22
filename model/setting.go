package model

import (
	"time"
)

// GlobalSetting model
type GlobalSetting struct {
	EndpointAddress     string    `json:"endpoint_address"`
	DNSServers          []string  `json:"dns_servers"`
	MTU                 int       `json:"mtu,string"`
	PersistentKeepalive int       `json:"persistent_keepalive,string"`
	FirewallMark        string    `json:"firewall_mark"`
	Table               string    `json:"table"`
	ConfigFilePath      string    `json:"config_file_path"`
	IPForwardDesired    bool      `json:"ip_forward_desired"`
	GlobalDNSOverride   bool      `json:"global_dns_override"`
	PersistWgConfOnSave bool      `json:"persist_wg_conf_on_save"`
	AutoApplyWGOnSave   bool      `json:"auto_apply_wg_on_save"`
	AlertEmailOnPeerDisconnect bool   `json:"alert_email_on_peer_disconnect"`
	LogRetentionDays           int    `json:"log_retention_days"`
	WebhookAlertsEnabled       bool   `json:"webhook_alerts_enabled"`
	WebhookURL                 string `json:"webhook_url"`
	SessionTimeoutMinutes      int    `json:"session_timeout_minutes"`
	TOTPEnabled                bool   `json:"totp_enabled"`
	UILanguage                 string `json:"ui_language"`
	UITheme                    string `json:"ui_theme"`
	RealtimeStatsEnabled       bool   `json:"realtime_stats_enabled"`
	UpdatedAt           time.Time `json:"updated_at"`
}
