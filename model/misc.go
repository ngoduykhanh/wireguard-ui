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
}
