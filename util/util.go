package util

import (
	"fmt"
	"net"
	"strings"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

// BuildClientConfig to create wireguard client config string
func BuildClientConfig(client model.Client, server model.Server, setting model.GlobalSetting) string {
	// Interface section
	clientAddress := fmt.Sprintf("Address = %s", strings.Join(client.AllocatedIPs, ","))
	clientPrivateKey := fmt.Sprintf("PrivateKey = %s", client.PrivateKey)
	clientDNS := fmt.Sprintf("DNS = %s", strings.Join(setting.DNSServers, ","))

	// Peer section
	peerPublicKey := fmt.Sprintf("PublicKey = %s", server.KeyPair.PublicKey)
	peerAllowedIPs := fmt.Sprintf("AllowedIPs = %s", strings.Join(client.AllowedIPs, ","))
	peerEndpoint := fmt.Sprintf("Endpoint = %s:%d", setting.EndpointAddress, server.Interface.ListenPort)
	peerPersistentKeepalive := fmt.Sprintf("PersistentKeepalive = %d", setting.PersistentKeepalive)

	// build the config as string
	strConfig := "[Interface]\n" +
		clientAddress + "\n" +
		clientPrivateKey + "\n" +
		clientDNS + "\n\n" +
		"[Peer]" + "\n" +
		peerPublicKey + "\n" +
		peerAllowedIPs + "\n" +
		peerEndpoint + "\n" +
		peerPersistentKeepalive + "\n"

	return strConfig
}

// ValidateCIDR to validate a network CIDR
func ValidateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return true
}

// ValidateCIDRList to validate a list of network CIDR
func ValidateCIDRList(cidrs []string) bool {
	for _, cidr := range cidrs {
		if ValidateCIDR(cidr) == false {
			return false
		}
	}
	return true
}

// ValidateAllowedIPs to validate allowed ip addresses in CIDR format
func ValidateAllowedIPs(cidrs []string) bool {
	if ValidateCIDRList(cidrs) == false {
		return false
	}
	return true
}

// ValidateServerAddresses to validate allowed ip addresses in CIDR format
func ValidateServerAddresses(cidrs []string) bool {
	if ValidateCIDRList(cidrs) == false {
		return false
	}
	return true
}

// ValidateIPAddress to validate the IPv4 and IPv6 address
func ValidateIPAddress(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}
	return true
}

// ValidateIPAddressList to validate a list of IPv4 and IPv6 addresses
func ValidateIPAddressList(ips []string) bool {
	for _, ip := range ips {
		if ValidateIPAddress(ip) == false {
			return false
		}
	}
	return true
}
