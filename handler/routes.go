package handler

import (
	"encoding/base64"
	"encoding/json"
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

		records, err := db.ReadAll("clients")
		if err != nil {
			log.Error("Cannot fetch clients from database: ", err)
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
			"name":           "Khanh",
			"clientDataList": clientDataList,
		})
	}
}

// NewClient handler
func NewClient() echo.HandlerFunc {
	return func(c echo.Context) error {
		client := new(model.Client)
		c.Bind(client)

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
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot access database"})
		}
		db.Write("clients", client.ID, client)
		log.Infof("Created wireguard client: %v", client)

		return c.JSON(http.StatusOK, client)
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
			"name":            "Khanh",
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
			"name":           "Khanh",
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
