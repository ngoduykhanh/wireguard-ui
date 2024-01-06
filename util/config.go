package util

import (
	"net"
	"strings"

	"github.com/labstack/gommon/log"
)

// Runtime config
var (
	DisableLogin       bool
	BindAddress        string
	SmtpHostname       string
	SmtpPort           int
	SmtpUsername       string
	SmtpPassword       string
	SmtpNoTLSCheck     bool
	SmtpEncryption     string
	SmtpAuthType       string
	SmtpHelo           string
	SendgridApiKey     string
	EmailFrom          string
	EmailFromName      string
	SessionSecret      [64]byte
	SessionMaxDuration int64
	WgConfTemplate     string
	BasePath           string
	SubnetRanges       map[string]([]*net.IPNet)
	SubnetRangesOrder  []string
)

const (
	DefaultUsername                        = "admin"
	DefaultPassword                        = "admin"
	DefaultIsAdmin                         = true
	DefaultServerAddress                   = "10.252.1.0/24"
	DefaultServerPort                      = 51820
	DefaultDNS                             = "1.1.1.1"
	DefaultMTU                             = 1450
	DefaultPersistentKeepalive             = 15
	DefaultFirewallMark                    = "0xca6c" // i.e. 51820
	DefaultTable                           = "auto"
	DefaultConfigFilePath                  = "/etc/wireguard/wg0.conf"
	UsernameEnvVar                         = "WGUI_USERNAME"
	PasswordEnvVar                         = "WGUI_PASSWORD"
	PasswordFileEnvVar                     = "WGUI_PASSWORD_FILE"
	PasswordHashEnvVar                     = "WGUI_PASSWORD_HASH"
	PasswordHashFileEnvVar                 = "WGUI_PASSWORD_HASH_FILE"
	FaviconFilePathEnvVar                  = "WGUI_FAVICON_FILE_PATH"
	EndpointAddressEnvVar                  = "WGUI_ENDPOINT_ADDRESS"
	DNSEnvVar                              = "WGUI_DNS"
	MTUEnvVar                              = "WGUI_MTU"
	PersistentKeepaliveEnvVar              = "WGUI_PERSISTENT_KEEPALIVE"
	FirewallMarkEnvVar                     = "WGUI_FIREWALL_MARK"
	TableEnvVar                            = "WGUI_TABLE"
	ConfigFilePathEnvVar                   = "WGUI_CONFIG_FILE_PATH"
	LogLevel                               = "WGUI_LOG_LEVEL"
	ServerAddressesEnvVar                  = "WGUI_SERVER_INTERFACE_ADDRESSES"
	ServerListenPortEnvVar                 = "WGUI_SERVER_LISTEN_PORT"
	ServerPostUpScriptEnvVar               = "WGUI_SERVER_POST_UP_SCRIPT"
	ServerPostDownScriptEnvVar             = "WGUI_SERVER_POST_DOWN_SCRIPT"
	DefaultClientAllowedIpsEnvVar          = "WGUI_DEFAULT_CLIENT_ALLOWED_IPS"
	DefaultClientExtraAllowedIpsEnvVar     = "WGUI_DEFAULT_CLIENT_EXTRA_ALLOWED_IPS"
	DefaultClientUseServerDNSEnvVar        = "WGUI_DEFAULT_CLIENT_USE_SERVER_DNS"
	DefaultClientEnableAfterCreationEnvVar = "WGUI_DEFAULT_CLIENT_ENABLE_AFTER_CREATION"
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

func ParseSubnetRanges(subnetRangesStr string) map[string]([]*net.IPNet) {
	subnetRanges := map[string]([]*net.IPNet){}
	if subnetRangesStr == "" {
		return subnetRanges
	}
	cidrSet := map[string]bool{}
	subnetRangesStr = strings.TrimSpace(subnetRangesStr)
	subnetRangesStr = strings.Trim(subnetRangesStr, ";:,")
	ranges := strings.Split(subnetRangesStr, ";")
	for _, rng := range ranges {
		rng = strings.TrimSpace(rng)
		rngSpl := strings.Split(rng, ":")
		if len(rngSpl) != 2 {
			log.Warnf("Unable to parse subnet range: %v. Skipped.", rng)
			continue
		}
		rngName := strings.TrimSpace(rngSpl[0])
		subnetRanges[rngName] = make([]*net.IPNet, 0)
		cidrs := strings.Split(rngSpl[1], ",")
		for _, cidr := range cidrs {
			cidr = strings.TrimSpace(cidr)
			_, net, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Warnf("[%v] Unable to parse CIDR: %v. Skipped.", rngName, cidr)
				continue
			}
			if cidrSet[net.String()] {
				log.Warnf("[%v] CIDR already exists: %v. Skipped.", rngName, net.String())
				continue
			}
			cidrSet[net.String()] = true
			subnetRanges[rngName] = append(subnetRanges[rngName], net)
		}
		if len(subnetRanges[rngName]) == 0 {
			delete(subnetRanges, rngName)
		} else {
			SubnetRangesOrder = append(SubnetRangesOrder, rngName)
		}
	}
	return subnetRanges
}
