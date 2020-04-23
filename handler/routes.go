package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/util"
	"github.com/rs/xid"
	"github.com/sdomino/scribble"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardClients handler
func WireGuardClients() echo.HandlerFunc {
	return func(c echo.Context) error {
		// initialize database directory
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
		}

		// read server information
		serverInterface := model.ServerInterface{}
		if err := db.Read("server", "interfaces", &serverInterface); err != nil {
			log.Error("Cannot fetch server interface config from database: ", err)
		}

		serverKeyPair := model.ServerKeypair{}
		if err := db.Read("server", "keypair", &serverKeyPair); err != nil {
			log.Error("Cannot fetch server key pair from database: ", err)
		}

		// read global settings
		globalSettings := model.GlobalSetting{}
		if err := db.Read("server", "global_settings", &globalSettings); err != nil {
			log.Error("Cannot fetch global settings from database: ", err)
		}

		server := model.Server{}
		server.Interface = &serverInterface
		server.KeyPair = &serverKeyPair

		// read client information and build a client list
		records, err := db.ReadAll("clients")
		if err != nil {
			log.Error("Cannot fetch clients from database: ", err)
		}

		clientDataList := []model.ClientData{}
		for _, f := range records {
			client := model.Client{}
			clientData := model.ClientData{}

			// get client info
			if err := json.Unmarshal([]byte(f), &client); err != nil {
				log.Error("Cannot decode client json structure: ", err)
			}
			clientData.Client = &client

			// generate client qrcode image in base64
			png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
			if err != nil {
				log.Error("Cannot generate QRCode: ", err)
			}
			clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))

			// create the list of clients and their qrcode data
			clientDataList = append(clientDataList, clientData)
		}

		return c.Render(http.StatusOK, "clients.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: ""},
			"clientDataList": clientDataList,
		})
	}
}

// NewClient handler
func NewClient() echo.HandlerFunc {
	return func(c echo.Context) error {
		client := new(model.Client)
		c.Bind(client)

		// initialize db
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot access database"})
		}

		// read server information
		serverInterface := model.ServerInterface{}
		if err := db.Read("server", "interfaces", &serverInterface); err != nil {
			log.Error("Cannot fetch server interface config from database: ", err)
		}

		// validate the input Allocation IPs
		allocatedIPs, err := util.GetAllocatedIPs()
		check, err := util.ValidateIPAllocation(serverInterface.Addresses, allocatedIPs, client.AllocatedIPs)
		if !check {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, fmt.Sprintf("%s", err)})
		}

		// validate the input AllowedIPs
		if util.ValidateAllowedIPs(client.AllowedIPs) == false {
			log.Warnf("Invalid Allowed IPs input from user: %v", client.AllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Allowed IPs must be in CIDR format"})
		}

		// gen ID
		guid := xid.New()
		client.ID = guid.String()

		// gen Wireguard key pair
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Error("Cannot generate wireguard key pair: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
		}
		client.PrivateKey = key.String()
		client.PublicKey = key.PublicKey().String()
		client.CreatedAt = time.Now().UTC()
		client.UpdatedAt = client.CreatedAt

		// write client to the database
		db.Write("clients", client.ID, client)
		log.Infof("Created wireguard client: %v", client)

		return c.JSON(http.StatusOK, client)
	}
}

// SetClientStatus handler to enable / disable a client
func SetClientStatus() echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		clientID := data["id"].(string)
		status := data["status"].(bool)

		// initialize database directory
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
		}

		client := model.Client{}
		if err := db.Read("clients", clientID, &client); err != nil {
			log.Error("Cannot fetch server interface config from database: ", err)
		}

		client.Enabled = status
		db.Write("clients", clientID, &client)
		log.Infof("Changed client %s enabled status to %v", client.ID, status)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "ok"})
	}
}

// RemoveClient handler
func RemoveClient() echo.HandlerFunc {
	return func(c echo.Context) error {
		client := new(model.Client)
		c.Bind(client)

		// delete client from database
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot access database"})
		}
		if err := db.Delete("clients", client.ID); err != nil {
			log.Error("Cannot delete wireguard client: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot delete client from database"})
		}

		log.Infof("Removed wireguard client: %v", client)
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Client removed"})
	}
}

// WireGuardServer handler
func WireGuardServer() echo.HandlerFunc {
	return func(c echo.Context) error {
		// initialize database directory
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
		}

		serverInterface := model.ServerInterface{}
		if err := db.Read("server", "interfaces", &serverInterface); err != nil {
			log.Error("Cannot fetch server interface config from database: ", err)
		}

		serverKeyPair := model.ServerKeypair{}
		if err := db.Read("server", "keypair", &serverKeyPair); err != nil {
			log.Error("Cannot fetch server key pair from database: ", err)
		}

		return c.Render(http.StatusOK, "server.html", map[string]interface{}{
			"baseData":        model.BaseData{Active: "wg-server"},
			"serverInterface": serverInterface,
			"serverKeyPair":   serverKeyPair,
		})
	}
}

// WireGuardServerInterfaces handler
func WireGuardServerInterfaces() echo.HandlerFunc {
	return func(c echo.Context) error {
		serverInterface := new(model.ServerInterface)
		c.Bind(serverInterface)

		// validate the input addresses
		if util.ValidateServerAddresses(serverInterface.Addresses) == false {
			log.Warnf("Invalid server interface addresses input from user: %v", serverInterface.Addresses)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Interface IP address must be in CIDR format"})
		}

		serverInterface.UpdatedAt = time.Now().UTC()

		// write config to the database
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot access database"})
		}
		db.Write("server", "interfaces", serverInterface)
		log.Infof("Updated wireguard server interfaces settings: %v", serverInterface)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated interface addresses successfully"})
	}
}

// WireGuardServerKeyPair handler to generate private and public keys
func WireGuardServerKeyPair() echo.HandlerFunc {
	return func(c echo.Context) error {
		// gen Wireguard key pair
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Error("Cannot generate wireguard key pair: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
		}

		serverKeyPair := new(model.ServerKeypair)
		serverKeyPair.PrivateKey = key.String()
		serverKeyPair.PublicKey = key.PublicKey().String()
		serverKeyPair.UpdatedAt = time.Now().UTC()

		// write config to the database
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot access database"})
		}
		db.Write("server", "keypair", serverKeyPair)
		log.Infof("Updated wireguard server interfaces settings: %v", serverKeyPair)

		return c.JSON(http.StatusOK, serverKeyPair)
	}
}

// GlobalSettings handler
func GlobalSettings() echo.HandlerFunc {
	return func(c echo.Context) error {
		// initialize database directory
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
		}

		globalSettings := model.GlobalSetting{}
		if err := db.Read("server", "global_settings", &globalSettings); err != nil {
			log.Error("Cannot fetch global settings from database: ", err)
		}

		return c.Render(http.StatusOK, "global_settings.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: "global-settings"},
			"globalSettings": globalSettings,
		})
	}
}

// GlobalSettingSubmit handler to update the global settings
func GlobalSettingSubmit() echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings := new(model.GlobalSetting)
		c.Bind(globalSettings)

		// validate the input dns server list
		if util.ValidateIPAddressList(globalSettings.DNSServers) == false {
			log.Warnf("Invalid DNS server list input from user: %v", globalSettings.DNSServers)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid DNS server address"})
		}

		globalSettings.UpdatedAt = time.Now().UTC()

		// write config to the database
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot access database"})
		}
		db.Write("server", "global_settings", globalSettings)
		log.Infof("Updated global settings: %v", globalSettings)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated global settings successfully"})
	}
}

// MachineIPAddresses handler to get local interface ip addresses
func MachineIPAddresses() echo.HandlerFunc {
	return func(c echo.Context) error {
		// get private ip addresses
		interfaceList, err := util.GetInterfaceIPs()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get machine ip addresses"})
		}

		// get public ip address
		// TODO: Remove the go-external-ip dependency
		publicInterface, err := util.GetPublicIP()
		if err != nil {
			log.Warn("Cannot get machine public ip address: ", err)
		} else {
			interfaceList = append(interfaceList, publicInterface)
		}

		return c.JSON(http.StatusOK, interfaceList)
	}
}

// SuggestIPAllocation handler to get the list of ip address for client
func SuggestIPAllocation() echo.HandlerFunc {
	return func(c echo.Context) error {
		// initialize database directory
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
		}

		// read server information
		serverInterface := model.ServerInterface{}
		if err := db.Read("server", "interfaces", &serverInterface); err != nil {
			log.Error("Cannot fetch server interface config from database: ", err)
		}

		// return the list of suggestedIPs
		// we take the first available ip address from
		// each server's network addresses.
		suggestedIPs := make([]string, 0)
		allocatedIPs, err := util.GetAllocatedIPs()
		if err != nil {
			log.Error("Cannot suggest ip allocation. Failed to get list of allocated ip addresses: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot suggest ip allocation: failed to get list of allocated ip addresses"})
		}
		for _, cidr := range serverInterface.Addresses {
			ip, err := util.GetAvailableIP(cidr, allocatedIPs)
			if err != nil {
				log.Error("Failed to get available ip from a CIDR: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, fmt.Sprintf("Cannot suggest ip allocation: failed to get available ip from network %s", cidr)})
			}
			suggestedIPs = append(suggestedIPs, fmt.Sprintf("%s/32", ip))
		}

		return c.JSON(http.StatusOK, suggestedIPs)
	}
}

// ApplyServerConfig handler to write config file and restart Wireguard server
func ApplyServerConfig() echo.HandlerFunc {
	return func(c echo.Context) error {
		// initialize database directory
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
		}

		// read server information
		serverInterface := model.ServerInterface{}
		if err := db.Read("server", "interfaces", &serverInterface); err != nil {
			log.Error("Cannot fetch server interface config from database: ", err)
		}

		serverKeyPair := model.ServerKeypair{}
		if err := db.Read("server", "keypair", &serverKeyPair); err != nil {
			log.Error("Cannot fetch server key pair from database: ", err)
		}

		server := model.Server{}
		server.Interface = &serverInterface
		server.KeyPair = &serverKeyPair

		// read global settings
		globalSettings := model.GlobalSetting{}
		if err := db.Read("server", "global_settings", &globalSettings); err != nil {
			log.Error("Cannot fetch global settings from database: ", err)
		}

		// read client information and build a client list
		records, err := db.ReadAll("clients")
		if err != nil {
			log.Error("Cannot fetch clients from database: ", err)
		}

		clientDataList := []model.ClientData{}
		for _, f := range records {
			client := model.Client{}
			clientData := model.ClientData{}

			// get client info
			if err := json.Unmarshal([]byte(f), &client); err != nil {
				log.Error("Cannot decode client json structure: ", err)
			}
			clientData.Client = &client

			// create the list of clients and their qrcode data
			clientDataList = append(clientDataList, clientData)
		}

		// Write config file
		err = util.WriteWireGuardServerConfig(server, clientDataList, globalSettings)
		if err != nil {
			log.Error("Cannot apply server config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, fmt.Sprintf("Cannot apply server config: %v", err)})
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Applied server config successfully"})
	}
}
