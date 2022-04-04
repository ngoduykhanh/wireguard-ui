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
	ConfigFilePath      string    `json:"config_file_path"`
	EmailSubject        string    `json:"email_subject"`
	EmailContent        string    `json:"email_content"`
	UpdatedAt           time.Time `json:"updated_at"`
}
