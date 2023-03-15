package model

// Interface model
type Interface struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
}

// BaseData struct to pass value to the base template
type BaseData struct {
	Active      string
	CurrentUser string
	Admin       bool
}

// ClientServerHashes struct, to save hashes to detect changes
type ClientServerHashes struct {
	Client string `json:"client"`
	Server string `json:"server"`
}
