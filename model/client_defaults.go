package model

// Defaults for creation of new clients used in the templates
type ClientDefaults struct {
	AllowedIps          []string
	ExtraAllowedIps     []string
	UseServerDNS        bool
	EnableAfterCreation bool
}
