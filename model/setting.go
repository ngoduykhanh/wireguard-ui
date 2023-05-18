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
	ConfigFilePath      string    `json:"config_file_path"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type EmailSetting struct {
	SendgridApiKey      string `json:"sendgrid_api_key"`
	EmailFromName       string `json:"email_from_name"`
	EmailFrom           string `json:"email_from"`
	SmtpHostname        string `json:"smtp_hostname"`
	SmtpPort            int    `json:"smtp_port"`
	SmtpUsername        string `json:"smtp_username"`
	SmtpPassword        string `json:"smtp_password"`
	SmtpNoTLSCheck      bool   `json:"smtp_no_tls_check"`
	SmtpAuthType        string `json:"smtp_auth_type"`
	SmtpEncryption      string `json:"smtp_encryption"`
	DefaultEmailSubject string `json:"default_email_subject"`
	DefaultEmailContent string `json:"default_email_content"`
}
