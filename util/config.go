package util

// Runtime config
var (
	DisableLogin   bool
	BindAddress    string
	SendgridApiKey string
	EmailFrom      string
	EmailFromName  string
	EmailSubject   string
	EmailContent   string
	SessionSecret  []byte
)

const (
	DefaultUsername            = "admin"
	DefaultPassword            = "admin"
	DefaultServerAddress       = "10.252.1.0/24"
	DefaultServerPort          = 51820
	DefaultDNS                 = "1.1.1.1"
	DefaultMTU                 = 1450
	DefaultPersistentKeepalive = 15
	DefaultConfigFilePath      = "/etc/wireguard/wg0.conf"
	UsernameEnvVar             = "WGUI_USERNAME"
	PasswordEnvVar             = "WGUI_PASSWORD"
)
