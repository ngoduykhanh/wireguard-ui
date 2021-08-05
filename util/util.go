package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"
	externalip "github.com/glendc/go-external-ip"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/sdomino/scribble"
)

// BuildClientConfig to create wireguard client config string
func BuildClientConfig(client model.Client, server model.Server, setting model.GlobalSetting) string {
	// Interface section
	clientAddress := fmt.Sprintf("Address = %s", strings.Join(client.AllocatedIPs, ","))
	clientPrivateKey := fmt.Sprintf("PrivateKey = %s", client.PrivateKey)
	clientDNS := ""
	if client.UseServerDNS {
		clientDNS = fmt.Sprintf("DNS = %s", strings.Join(setting.DNSServers, ","))
	}

	// Peer section
	peerPublicKey := fmt.Sprintf("PublicKey = %s", server.KeyPair.PublicKey)
	peerPresharedKey := fmt.Sprintf("PresharedKey = %s", client.PresharedKey)
	peerAllowedIPs := fmt.Sprintf("AllowedIPs = %s", strings.Join(client.AllowedIPs, ","))

	desiredHost := setting.EndpointAddress
	desiredPort := server.Interface.ListenPort
	if strings.Contains(desiredHost, ":") {
		split := strings.Split(desiredHost, ":")
		desiredHost = split[0]
		if n, err := strconv.Atoi(split[1]); err == nil {
			desiredPort = n
		} else {
			log.Error("Endpoint appears to be incorrectly formated: ", err)
		}
	}
	peerEndpoint := fmt.Sprintf("Endpoint = %s:%d", desiredHost, desiredPort)

	peerPersistentKeepalive := fmt.Sprintf("PersistentKeepalive = %d", setting.PersistentKeepalive)

	// build the config as string
	strConfig := "[Interface]\n" +
		clientAddress + "\n" +
		clientPrivateKey + "\n" +
		clientDNS + "\n\n" +
		"[Peer]" + "\n" +
		peerPublicKey + "\n" +
		peerPresharedKey + "\n" +
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

// GetInterfaceIPs to get local machine's interface ip addresses
func GetInterfaceIPs() ([]model.Interface, error) {
	// get machine's interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var interfaceList = []model.Interface{}

	// get interface's ip addresses
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}

			iface := model.Interface{}
			iface.Name = i.Name
			iface.IPAddress = ip.String()
			interfaceList = append(interfaceList, iface)
		}
	}
	return interfaceList, err
}

// GetPublicIP to get machine's public ip address
func GetPublicIP() (model.Interface, error) {
	// set time out to 5 seconds
	cfg := externalip.ConsensusConfig{}
	cfg.Timeout = time.Second * 5
	consensus := externalip.NewConsensus(&cfg, nil)

	// add trusted voters
	consensus.AddVoter(externalip.NewHTTPSource("http://checkip.amazonaws.com/"), 1)
	consensus.AddVoter(externalip.NewHTTPSource("http://whatismyip.akamai.com"), 1)
	consensus.AddVoter(externalip.NewHTTPSource("http://ifconfig.top"), 1)

	publicInterface := model.Interface{}
	publicInterface.Name = "Public Address"

	ip, err := consensus.ExternalIP()
	if err != nil {
		publicInterface.IPAddress = "N/A"
	}
	publicInterface.IPAddress = ip.String()

	return publicInterface, err
}

// GetIPFromCIDR get ip from CIDR
func GetIPFromCIDR(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// GetAllocatedIPs to get all ip addresses allocated to clients and server
func GetAllocatedIPs(ignoreClientID string) ([]string, error) {
	allocatedIPs := make([]string, 0)

	// initialize database directory
	dir := "./db"
	db, err := scribble.New(dir, nil)
	if err != nil {
		return nil, err
	}

	// read server information
	serverInterface := model.ServerInterface{}
	if err := db.Read("server", "interfaces", &serverInterface); err != nil {
		return nil, err
	}

	// append server's addresses to the result
	for _, cidr := range serverInterface.Addresses {
		ip, err := GetIPFromCIDR(cidr)
		if err != nil {
			return nil, err
		}
		allocatedIPs = append(allocatedIPs, ip)
	}

	// read client information
	records, err := db.ReadAll("clients")
	if err != nil {
		return nil, err
	}

	// append client's addresses to the result
	for _, f := range records {
		client := model.Client{}
		if err := json.Unmarshal([]byte(f), &client); err != nil {
			return nil, err
		}

		if client.ID != ignoreClientID {
			for _, cidr := range client.AllocatedIPs {
				ip, err := GetIPFromCIDR(cidr)
				if err != nil {
					return nil, err
				}
				allocatedIPs = append(allocatedIPs, ip)
			}
		}
	}

	return allocatedIPs, nil
}

// inc from https://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetBroadcastIP func to get the broadcast ip address of a network
func GetBroadcastIP(n *net.IPNet) net.IP {
	var broadcast net.IP
	if len(n.IP) == 4 {
		broadcast = net.ParseIP("0.0.0.0").To4()
	} else {
		broadcast = net.ParseIP("::")
	}
	for i := 0; i < len(n.IP); i++ {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast
}

// GetAvailableIP get the ip address that can be allocated from an CIDR
func GetAvailableIP(cidr string, allocatedList []string) (string, error) {
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	broadcastAddr := GetBroadcastIP(net).String()
	networkAddr := net.IP.String()

	for ip := ip.Mask(net.Mask); net.Contains(ip); inc(ip) {
		available := true
		suggestedAddr := ip.String()
		for _, allocatedAddr := range allocatedList {
			if suggestedAddr == allocatedAddr {
				available = false
				break
			}
		}
		if available && suggestedAddr != networkAddr && suggestedAddr != broadcastAddr {
			return suggestedAddr, nil
		}
	}

	return "", errors.New("no more available ip address")
}

// ValidateIPAllocation to validate the list of client's ip allocation
// They must have a correct format and available in serverAddresses space
func ValidateIPAllocation(serverAddresses []string, ipAllocatedList []string, ipAllocationList []string) (bool, error) {
	for _, clientCIDR := range ipAllocationList {
		ip, _, _ := net.ParseCIDR(clientCIDR)

		// clientCIDR must be in CIDR format
		if ip == nil {
			return false, fmt.Errorf("Invalid ip allocation input %s. Must be in CIDR format", clientCIDR)
		}

		// return false immediately if the ip is already in use (in ipAllocatedList)
		for _, item := range ipAllocatedList {
			if item == ip.String() {
				return false, fmt.Errorf("IP %s already allocated", ip)
			}
		}

		// even if it is not in use, we still need to check if it
		// belongs to a network of the server.
		var isValid bool = false
		for _, serverCIDR := range serverAddresses {
			_, serverNet, _ := net.ParseCIDR(serverCIDR)
			if serverNet.Contains(ip) {
				isValid = true
				break
			}
		}

		// current ip allocation is valid, check the next one
		if isValid {
			continue
		} else {
			return false, fmt.Errorf("IP %s does not belong to any network addresses of WireGuard server", ip)
		}
	}

	return true, nil
}

// WriteWireGuardServerConfig to write Wireguard server config. e.g. wg0.conf
func WriteWireGuardServerConfig(tmplBox *rice.Box, serverConfig model.Server, clientDataList []model.ClientData, globalSettings model.GlobalSetting) error {
	// read wg.conf template file to string
	tmplWireguardConf, err := tmplBox.String("wg.conf")
	if err != nil {
		return err
	}

	// parse the template
	t, err := template.New("wg_config").Parse(tmplWireguardConf)
	if err != nil {
		return err
	}

	// write config file to disk
	f, err := os.Create(globalSettings.ConfigFilePath)
	if err != nil {
		return err
	}

	config := map[string]interface{}{
		"serverConfig":   serverConfig,
		"clientDataList": clientDataList,
		"globalSettings": globalSettings,
	}

	err = t.Execute(f, config)
	if err != nil {
		return err
	}
	f.Close()

	return nil
}
