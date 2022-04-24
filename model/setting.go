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
	ForwardMark         string    `json:"forward_mark"`
	ConfigFilePath      string    `json:"config_file_path"`
	UpdatedAt           time.Time `json:"updated_at"`
}
