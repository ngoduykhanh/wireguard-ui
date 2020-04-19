package util

import (
	"fmt"
	"net"
	"strings"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

const wgConfigDNS = "1.1.1.1, 8.8.8.8"
const wgConfigPersistentKeepalive = 15
const wgConfigEndpoint = "wireguard.example.com:56231"
const wgConfigServerPublicKey = "/OKCBc8PxIqCpgqlE9G1kSaTecdAvYf3loEwFj6MXDc="

// BuildClientConfig to create wireguard client config string
func BuildClientConfig(client model.Client) string {
	// Interface section
	clientAddress := fmt.Sprintf("Address = %s", strings.Join(client.AllocatedIPs, ","))
	clientPrivateKey := fmt.Sprintf("PrivateKey = %s", client.PrivateKey)
	clientDNS := fmt.Sprintf("DNS = %s", wgConfigDNS)

	// Peer section
	peerPublicKey := fmt.Sprintf("PublicKey = %s", wgConfigServerPublicKey)
	peerAllowedIPs := fmt.Sprintf("AllowedIPs = %s", strings.Join(client.AllowedIPs, ","))
	peerEndpoint := fmt.Sprintf("Endpoint = %s", wgConfigEndpoint)
	peerPersistentKeepalive := fmt.Sprintf("PersistentKeepalive = %d", wgConfigPersistentKeepalive)

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
