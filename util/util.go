package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"golang.org/x/mod/sumdb/dirhash"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	externalip "github.com/glendc/go-external-ip"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/sdomino/scribble"
)

// BuildClientConfig to create wireguard client config string
func BuildClientConfig(client model.Client, server model.Server, setting model.GlobalSetting) string {
	// Interface section
	clientAddress := fmt.Sprintf("Address = %s\n", strings.Join(client.AllocatedIPs, ","))
	clientPrivateKey := fmt.Sprintf("PrivateKey = %s\n", client.PrivateKey)
	clientDNS := ""
	if client.UseServerDNS {
		clientDNS = fmt.Sprintf("DNS = %s\n", strings.Join(setting.DNSServers, ","))
	}
	clientMTU := ""
	if setting.MTU > 0 {
		clientMTU = fmt.Sprintf("MTU = %d\n", setting.MTU)
	}

	// Peer section
	peerPublicKey := fmt.Sprintf("PublicKey = %s\n", server.KeyPair.PublicKey)
	peerPresharedKey := ""
	if client.PresharedKey != "" {
		peerPresharedKey = fmt.Sprintf("PresharedKey = %s\n", client.PresharedKey)
	}

	peerAllowedIPs := fmt.Sprintf("AllowedIPs = %s\n", strings.Join(client.AllowedIPs, ","))

	desiredHost := setting.EndpointAddress
	desiredPort := server.Interface.ListenPort
	if strings.Contains(desiredHost, ":") {
		split := strings.Split(desiredHost, ":")
		desiredHost = split[0]
		if n, err := strconv.Atoi(split[1]); err == nil {
			desiredPort = n
		} else {
			log.Error("Endpoint appears to be incorrectly formatted: ", err)
		}
	}
	peerEndpoint := fmt.Sprintf("Endpoint = %s:%d\n", desiredHost, desiredPort)

	peerPersistentKeepalive := ""
	if setting.PersistentKeepalive > 0 {
		peerPersistentKeepalive = fmt.Sprintf("PersistentKeepalive = %d\n", setting.PersistentKeepalive)
	}

	// build the config as string
	strConfig := "[Interface]\n" +
		clientAddress +
		clientPrivateKey +
		clientDNS +
		clientMTU +
		"\n[Peer]\n" +
		peerPublicKey +
		peerPresharedKey +
		peerAllowedIPs +
		peerEndpoint +
		peerPersistentKeepalive

	return strConfig
}

// ClientDefaultsFromEnv to read the default values for creating a new client from the environment or use sane defaults
func ClientDefaultsFromEnv() model.ClientDefaults {
	clientDefaults := model.ClientDefaults{}
	clientDefaults.AllowedIps = LookupEnvOrStrings(DefaultClientAllowedIpsEnvVar, []string{"0.0.0.0/0"})
	clientDefaults.ExtraAllowedIps = LookupEnvOrStrings(DefaultClientExtraAllowedIpsEnvVar, []string{})
	clientDefaults.UseServerDNS = LookupEnvOrBool(DefaultClientUseServerDNSEnvVar, true)
	clientDefaults.EnableAfterCreation = LookupEnvOrBool(DefaultClientEnableAfterCreationEnvVar, true)

	return clientDefaults
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
func ValidateCIDRList(cidrs []string, allowEmpty bool) bool {
	for _, cidr := range cidrs {
		if allowEmpty {
			if len(cidr) > 0 {
				if ValidateCIDR(cidr) == false {
					return false
				}
			}
		} else {
			if ValidateCIDR(cidr) == false {
				return false
			}
		}
	}
	return true
}

// ValidateAllowedIPs to validate allowed ip addresses in CIDR format
func ValidateAllowedIPs(cidrs []string) bool {
	if ValidateCIDRList(cidrs, false) == false {
		return false
	}
	return true
}

// ValidateExtraAllowedIPs to validate extra Allowed ip addresses, allowing empty strings
func ValidateExtraAllowedIPs(cidrs []string) bool {
	if ValidateCIDRList(cidrs, true) == false {
		return false
	}
	return true
}

// ValidateServerAddresses to validate allowed ip addresses in CIDR format
func ValidateServerAddresses(cidrs []string) bool {
	if ValidateCIDRList(cidrs, false) == false {
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
	} else {
		publicInterface.IPAddress = ip.String()
	}

	// error handling happend above, no need to pass it through
	return publicInterface, nil
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
func WriteWireGuardServerConfig(tmplDir fs.FS, serverConfig model.Server, clientDataList []model.ClientData, usersList []model.User, globalSettings model.GlobalSetting) error {
	var tmplWireguardConf string

	// if set, read wg.conf template from WgConfTemplate
	if len(WgConfTemplate) > 0 {
		fileContentBytes, err := ioutil.ReadFile(WgConfTemplate)
		if err != nil {
			return err
		}
		tmplWireguardConf = string(fileContentBytes)
	} else {
		// read default wg.conf template file to string
		fileContent, err := StringFromEmbedFile(tmplDir, "wg.conf")
		if err != nil {
			return err
		}
		tmplWireguardConf = fileContent
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
		"usersList":      usersList,
	}

	err = t.Execute(f, config)
	if err != nil {
		return err
	}
	f.Close()

	return nil
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func LookupEnvOrBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.ParseBool(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "LookupEnvOrBool[%s]: %v\n", key, err)
		}
		return v
	}
	return defaultVal
}

func LookupEnvOrInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "LookupEnvOrInt[%s]: %v\n", key, err)
		}
		return v
	}
	return defaultVal
}

func LookupEnvOrStrings(key string, defaultVal []string) []string {
	if val, ok := os.LookupEnv(key); ok {
		return strings.Split(val, ",")
	}
	return defaultVal
}

func StringFromEmbedFile(embed fs.FS, filename string) (string, error) {
	file, err := embed.Open(filename)
	if err != nil {
		return "", err
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func ParseLogLevel(lvl string) (log.Lvl, error) {
	switch strings.ToLower(lvl) {
	case "debug":
		return log.DEBUG, nil
	case "info":
		return log.INFO, nil
	case "warn":
		return log.WARN, nil
	case "error":
		return log.ERROR, nil
	case "off":
		return log.OFF, nil
	default:
		return log.DEBUG, fmt.Errorf("not a valid log level: %s", lvl)
	}
}

// GetCurrentHash returns current hashes
func GetCurrentHash(db store.IStore) (string, string) {
	hashClients, _ := dirhash.HashDir(path.Join(db.GetPath(), "clients"), "prefix", dirhash.Hash1)
	files := append([]string(nil), "prefix/global_settings.json", "prefix/interfaces.json", "prefix/keypair.json")

	osOpen := func(name string) (io.ReadCloser, error) {
		return os.Open(filepath.Join(path.Join(db.GetPath(), "server"), strings.TrimPrefix(name, "prefix")))
	}
	hashServer, _ := dirhash.Hash1(files, osOpen)

	return hashClients, hashServer
}

func HashesChanged(db store.IStore) bool {
	old, _ := db.GetHashes()
	oldClient := old.Client
	oldServer := old.Server
	newClient, newServer := GetCurrentHash(db)

	if oldClient != newClient {
		//fmt.Println("Hash for client differs")
		return true
	}
	if oldServer != newServer {
		//fmt.Println("Hash for server differs")
		return true
	}
	return false
}

func UpdateHashes(db store.IStore) error {
	var clientServerHashes model.ClientServerHashes
	clientServerHashes.Client, clientServerHashes.Server = GetCurrentHash(db)
	return db.SaveHashes(clientServerHashes)
}
