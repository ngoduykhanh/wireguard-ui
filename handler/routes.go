package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/rs/xid"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ngoduykhanh/wireguard-ui/emailer"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// LoginPage handler
func LoginPage() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{})
	}
}

// Login for signing in handler
func Login(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := new(model.User)
		c.Bind(user)

		dbuser, err := db.GetUser()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot query user from DB"})
		}

		if user.Username == dbuser.Username && user.Password == dbuser.Password {
			// TODO: refresh the token
			sess, _ := session.Get("session", c)
			sess.Options = &sessions.Options{
				Path:     "/",
				MaxAge:   86400,
				HttpOnly: true,
			}

			// set session_token
			tokenUID := xid.New().String()
			sess.Values["username"] = user.Username
			sess.Values["session_token"] = tokenUID
			sess.Save(c.Request(), c.Response())

			// set session_token in cookie
			cookie := new(http.Cookie)
			cookie.Name = "session_token"
			cookie.Value = tokenUID
			cookie.Expires = time.Now().Add(24 * time.Hour)
			c.SetCookie(cookie)

			return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Logged in successfully"})
		}

		return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Invalid credentials"})
	}
}

// Logout to log a user out
func Logout() echo.HandlerFunc {
	return func(c echo.Context) error {
		clearSession(c)
		return c.Redirect(http.StatusTemporaryRedirect, "/login")
	}
}

// WireGuardClients handler
func WireGuardClients(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		clientDataList, err := db.GetClients(true)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot get client list: %v", err),
			})
		}

		return c.Render(http.StatusOK, "clients.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: "", CurrentUser: currentUser(c)},
			"clientDataList": clientDataList,
		})
	}
}

// GetClients handler return a list of Wireguard client data
func GetClients(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		clientDataList, err := db.GetClients(true)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot get client list: %v", err),
			})
		}

		return c.JSON(http.StatusOK, clientDataList)
	}
}

// GetClient handler return a of Wireguard client data
func GetClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		clientID := c.Param("id")
		clientData, err := db.GetClientByID(clientID, true)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		return c.JSON(http.StatusOK, clientData)
	}
}

// NewClient handler
func NewClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		var client model.Client
		c.Bind(&client)

		// read server information
		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot fetch server from database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}

		// validate the input Allocation IPs
		allocatedIPs, err := util.GetAllocatedIPs("")
		check, err := util.ValidateIPAllocation(server.Interface.Addresses, allocatedIPs, client.AllocatedIPs)
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

		presharedKey, err := wgtypes.GenerateKey()
		if err != nil {
			log.Error("Cannot generated preshared key: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot generate Wireguard preshared key",
			})
		}

		client.PrivateKey = key.String()
		client.PublicKey = key.PublicKey().String()
		client.PresharedKey = presharedKey.String()
		client.CreatedAt = time.Now().UTC()
		client.UpdatedAt = client.CreatedAt

		// write client to the database
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, err.Error(),
			})
		}
		log.Infof("Created wireguard client: %v", client)

		return c.JSON(http.StatusOK, client)
	}
}

// EmailClient handler to sent the configuration via email
func EmailClient(db store.IStore, mailer emailer.Emailer, emailSubject, emailContent string) echo.HandlerFunc {
	type clientIdEmailPayload struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}

	return func(c echo.Context) error {
		var payload clientIdEmailPayload
		c.Bind(&payload)
		// TODO validate email

		clientData, err := db.GetClientByID(payload.ID, true)
		if err != nil {
			log.Errorf("Cannot generate client id %s config file for downloading: %v", payload.ID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		// build config
		server, _ := db.GetServer()
		globalSettings, _ := db.GetGlobalSettings()
		config := util.BuildClientConfig(*clientData.Client, server, globalSettings)

		cfg_att := emailer.Attachment{"wg0.conf", []byte(config)}
		qrdata, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(clientData.QRCode, "data:image/png;base64,"))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "decoding: " + err.Error()})
		}
		qr_att := emailer.Attachment{"wg.png", qrdata}
		err = mailer.Send(
			clientData.Client.Name,
			payload.Email,
			emailSubject,
			emailContent,
			[]emailer.Attachment{cfg_att, qr_att},
		)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Email sent successfully"})
	}
}

// UpdateClient handler to update client information
func UpdateClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		var _client model.Client
		c.Bind(&_client)

		// validate client existence
		clientData, err := db.GetClientByID(_client.ID, false)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		server, err := db.GetServer()
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot fetch server config: %s", err),
			})
		}
		client := *clientData.Client
		// validate the input Allocation IPs
		allocatedIPs, err := util.GetAllocatedIPs(client.ID)
		check, err := util.ValidateIPAllocation(server.Interface.Addresses, allocatedIPs, _client.AllocatedIPs)
		if !check {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, fmt.Sprintf("%s", err)})
		}

		// validate the input AllowedIPs
		if util.ValidateAllowedIPs(_client.AllowedIPs) == false {
			log.Warnf("Invalid Allowed IPs input from user: %v", _client.AllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Allowed IPs must be in CIDR format"})
		}

		// map new data
		client.Name = _client.Name
		client.Email = _client.Email
		client.Enabled = _client.Enabled
		client.UseServerDNS = _client.UseServerDNS
		client.AllocatedIPs = _client.AllocatedIPs
		client.AllowedIPs = _client.AllowedIPs
		client.UpdatedAt = time.Now().UTC()

		// write to the database
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		log.Infof("Updated client information successfully => %v", client)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated client successfully"})
	}
}

// SetClientStatus handler to enable / disable a client
func SetClientStatus(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		clientID := data["id"].(string)
		status := data["status"].(bool)

		clientdata, err := db.GetClientByID(clientID, false)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, err.Error()})
		}

		client := *clientdata.Client

		client.Enabled = status
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		log.Infof("Changed client %s enabled status to %v", client.ID, status)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Changed client status successfully"})
	}
}

// DownloadClient handler
func DownloadClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientID := c.QueryParam("clientid")
		if clientID == "" {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Missing clientid parameter"})
		}

		clientData, err := db.GetClientByID(clientID, false)
		if err != nil {
			log.Errorf("Cannot generate client id %s config file for downloading: %v", clientID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		// build config
		server, err := db.GetServer()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		globalSettings, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		config := util.BuildClientConfig(*clientData.Client, server, globalSettings)

		// create io reader from string
		reader := strings.NewReader(config)

		// set response header for downloading
		c.Response().Header().Set(echo.HeaderContentDisposition, "attachment; filename=wg0.conf")
		return c.Stream(http.StatusOK, "text/plain", reader)
	}
}

// RemoveClient handler
func RemoveClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		client := new(model.Client)
		c.Bind(client)

		// delete client from database

		if err := db.DeleteClient(client.ID); err != nil {
			log.Error("Cannot delete wireguard client: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot delete client from database"})
		}

		log.Infof("Removed wireguard client: %v", client)
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Client removed"})
	}
}

// WireGuardServer handler
func WireGuardServer(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot get server config: ", err)
		}

		return c.Render(http.StatusOK, "server.html", map[string]interface{}{
			"baseData":        model.BaseData{Active: "wg-server", CurrentUser: currentUser(c)},
			"serverInterface": server.Interface,
			"serverKeyPair":   server.KeyPair,
		})
	}
}

// WireGuardServerInterfaces handler
func WireGuardServerInterfaces(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		var serverInterface model.ServerInterface
		c.Bind(&serverInterface)

		// validate the input addresses
		if util.ValidateServerAddresses(serverInterface.Addresses) == false {
			log.Warnf("Invalid server interface addresses input from user: %v", serverInterface.Addresses)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Interface IP address must be in CIDR format"})
		}

		serverInterface.UpdatedAt = time.Now().UTC()

		// write config to the database

		if err := db.SaveServerInterface(serverInterface); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Interface IP address must be in CIDR format"})
		}
		log.Infof("Updated wireguard server interfaces settings: %v", serverInterface)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated interface addresses successfully"})
	}
}

// WireGuardServerKeyPair handler to generate private and public keys
func WireGuardServerKeyPair(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		// gen Wireguard key pair
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Error("Cannot generate wireguard key pair: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
		}

		var serverKeyPair model.ServerKeypair
		serverKeyPair.PrivateKey = key.String()
		serverKeyPair.PublicKey = key.PublicKey().String()
		serverKeyPair.UpdatedAt = time.Now().UTC()

		if err := db.SaveServerKeyPair(serverKeyPair); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
		}
		log.Infof("Updated wireguard server interfaces settings: %v", serverKeyPair)

		return c.JSON(http.StatusOK, serverKeyPair)
	}
}

// GlobalSettings handler
func GlobalSettings(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		globalSettings, err := db.GetGlobalSettings()
		if err != nil {
			log.Error("Cannot get global settings: ", err)
		}

		return c.Render(http.StatusOK, "global_settings.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: "global-settings", CurrentUser: currentUser(c)},
			"globalSettings": globalSettings,
		})
	}
}

// Status handler
func Status(db store.IStore) echo.HandlerFunc {
	type PeerVM struct {
		Name              string
		Email             string
		PublicKey         string
		ReceivedBytes     int64
		TransmitBytes     int64
		LastHandshakeTime time.Time
		LastHandshakeRel  time.Duration
		Connected         bool
	}

	type DeviceVM struct {
		Name  string
		Peers []PeerVM
	}
	return func(c echo.Context) error {

		wgclient, err := wgctrl.New()
		if err != nil {
			return c.Render(http.StatusInternalServerError, "status.html", map[string]interface{}{
				"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c)},
				"error":    err.Error(),
				"devices":  nil,
			})
		}

		devices, err := wgclient.Devices()
		if err != nil {
			return c.Render(http.StatusInternalServerError, "status.html", map[string]interface{}{
				"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c)},
				"error":    err.Error(),
				"devices":  nil,
			})
		}

		devicesVm := make([]DeviceVM, 0, len(devices))
		if len(devices) > 0 {
			m := make(map[string]*model.Client)
			clients, err := db.GetClients(false)
			if err != nil {
				return c.Render(http.StatusInternalServerError, "status.html", map[string]interface{}{
					"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c)},
					"error":    err.Error(),
					"devices":  nil,
				})
			}
			for i := range clients {
				if clients[i].Client != nil {
					m[clients[i].Client.PublicKey] = clients[i].Client
				}
			}

			conv := map[bool]int{true: 1, false: 0}
			for i := range devices {
				devVm := DeviceVM{Name: devices[i].Name}
				for j := range devices[i].Peers {
					pVm := PeerVM{
						PublicKey:         devices[i].Peers[j].PublicKey.String(),
						ReceivedBytes:     devices[i].Peers[j].ReceiveBytes,
						TransmitBytes:     devices[i].Peers[j].TransmitBytes,
						LastHandshakeTime: devices[i].Peers[j].LastHandshakeTime,
						LastHandshakeRel:  time.Since(devices[i].Peers[j].LastHandshakeTime),
					}
					pVm.Connected = pVm.LastHandshakeRel.Minutes() < 3.

					if _client, ok := m[pVm.PublicKey]; ok {
						pVm.Name = _client.Name
						pVm.Email = _client.Email
					}
					devVm.Peers = append(devVm.Peers, pVm)
				}
				sort.SliceStable(devVm.Peers, func(i, j int) bool { return devVm.Peers[i].Name < devVm.Peers[j].Name })
				sort.SliceStable(devVm.Peers, func(i, j int) bool { return conv[devVm.Peers[i].Connected] > conv[devVm.Peers[j].Connected] })
				devicesVm = append(devicesVm, devVm)
			}
		}

		return c.Render(http.StatusOK, "status.html", map[string]interface{}{
			"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c)},
			"devices":  devicesVm,
			"error":    "",
		})
	}
}

// GlobalSettingSubmit handler to update the global settings
func GlobalSettingSubmit(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		var globalSettings model.GlobalSetting
		c.Bind(&globalSettings)

		// validate the input dns server list
		if util.ValidateIPAddressList(globalSettings.DNSServers) == false {
			log.Warnf("Invalid DNS server list input from user: %v", globalSettings.DNSServers)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid DNS server address"})
		}

		globalSettings.UpdatedAt = time.Now().UTC()

		// write config to the database
		if err := db.SaveGlobalSettings(globalSettings); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
		}

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
			// prepend public ip to the list
			interfaceList = append([]model.Interface{publicInterface}, interfaceList...)
		}

		return c.JSON(http.StatusOK, interfaceList)
	}
}

// SuggestIPAllocation handler to get the list of ip address for client
func SuggestIPAllocation(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot fetch server config from database: ", err)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
		}

		// return the list of suggestedIPs
		// we take the first available ip address from
		// each server's network addresses.
		suggestedIPs := make([]string, 0)
		allocatedIPs, err := util.GetAllocatedIPs("")
		if err != nil {
			log.Error("Cannot suggest ip allocation. Failed to get list of allocated ip addresses: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot suggest ip allocation: failed to get list of allocated ip addresses",
			})
		}
		for _, cidr := range server.Interface.Addresses {
			ip, err := util.GetAvailableIP(cidr, allocatedIPs)
			if err != nil {
				log.Error("Failed to get available ip from a CIDR: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
					false,
					fmt.Sprintf("Cannot suggest ip allocation: failed to get available ip from network %s", cidr),
				})
			}
			suggestedIPs = append(suggestedIPs, fmt.Sprintf("%s/32", ip))
		}

		return c.JSON(http.StatusOK, suggestedIPs)
	}
}

// ApplyServerConfig handler to write config file and restart Wireguard server
func ApplyServerConfig(db store.IStore, tmplBox *rice.Box) echo.HandlerFunc {
	return func(c echo.Context) error {

		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot get server config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get server config"})
		}

		clients, err := db.GetClients(false)
		if err != nil {
			log.Error("Cannot get client config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get client config"})
		}

		settings, err := db.GetGlobalSettings()
		if err != nil {
			log.Error("Cannot get global settings: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get global settings"})
		}

		// Write config file
		err = util.WriteWireGuardServerConfig(tmplBox, server, clients, settings)
		if err != nil {
			log.Error("Cannot apply server config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot apply server config: %v", err),
			})
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Applied server config successfully"})
	}
}
