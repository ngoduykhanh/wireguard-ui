package model

// ClientDefaults Defaults for creation of new clients used in the templates
type ClientDefaults struct {
	AllowedIps          []string `json:"allowed_ips"`
	ExtraAllowedIps     []string `json:"extra_allowed_ips"`
	UseServerDNS        bool     `json:"use_server_dns"`
	EnableAfterCreation bool     `json:"enable_after_creation"`
}
