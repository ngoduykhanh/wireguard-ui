package util

import "strings"

// Runtime config
var (
	DisableLogin   bool
	BindAddress    string
	SmtpHostname   string
	SmtpPort       int
	SmtpUsername   string
	SmtpPassword   string
	SmtpNoTLSCheck bool
	SmtpAuthType   string
	SendgridApiKey string
	EmailFrom      string
	EmailFromName  string
	EmailSubject   string
	EmailContent   string
	SessionSecret  []byte
	WgConfTemplate string
	BasePath       string
)

const (
	DefaultUsername            = "admin"
	DefaultPassword            = "admin"
	DefaultServerAddress       = "10.252.1.0/24"
	DefaultServerPort          = 51820
	DefaultDNS                 = "1.1.1.1"
	DefaultMTU                 = 1450
	DefaultPersistentKeepalive = 15
	DefaultForwardMark         = "0xca6c"
	DefaultConfigFilePath      = "/etc/wireguard/wg0.conf"
	UsernameEnvVar             = "WGUI_USERNAME"
	PasswordEnvVar             = "WGUI_PASSWORD"
)

func ParseBasePath(basePath string) string {
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if strings.HasSuffix(basePath, "/") {
		basePath = strings.TrimSuffix(basePath, "/")
	}
	return basePath
}
