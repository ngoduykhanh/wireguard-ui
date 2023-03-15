package handler

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

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

// Health check handler
func Health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}
}

func Favicon() echo.HandlerFunc {
	return func(c echo.Context) error {
		if favicon, ok := os.LookupEnv(util.FaviconFilePathEnvVar); ok {
			return c.File(favicon)
		}
		return c.Redirect(http.StatusFound, util.BasePath+"/static/custom/img/favicon.ico")
	}
}

// LoginPage handler
func LoginPage() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{})
	}
}

// Login for signing in handler
func Login(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		username := data["username"].(string)
		password := data["password"].(string)
		rememberMe := data["rememberMe"].(bool)

		dbuser, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot query user from DB"})
		}

		userCorrect := subtle.ConstantTimeCompare([]byte(username), []byte(dbuser.Username)) == 1

		var passwordCorrect bool
		if dbuser.PasswordHash != "" {
			match, err := util.VerifyHash(dbuser.PasswordHash, password)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot verify password"})
			}
			passwordCorrect = match
		} else {
			passwordCorrect = subtle.ConstantTimeCompare([]byte(password), []byte(dbuser.Password)) == 1
		}

		if userCorrect && passwordCorrect {
			// TODO: refresh the token
			ageMax := 0
			expiration := time.Now().Add(24 * time.Hour)
			if rememberMe {
				ageMax = 86400
				expiration.Add(144 * time.Hour)
			}
			sess, _ := session.Get("session", c)
			sess.Options = &sessions.Options{
				Path:     util.BasePath,
				MaxAge:   ageMax,
				HttpOnly: true,
			}

			// set session_token
			tokenUID := xid.New().String()
			sess.Values["username"] = dbuser.Username
			sess.Values["admin"] = dbuser.Admin
			sess.Values["session_token"] = tokenUID
			sess.Save(c.Request(), c.Response())

			// set session_token in cookie
			cookie := new(http.Cookie)
			cookie.Name = "session_token"
			cookie.Value = tokenUID
			cookie.Expires = expiration
			c.SetCookie(cookie)

			return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Logged in successfully"})
		}

		return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Invalid credentials"})
	}
}

// GetUsers handler return a JSON list of all users
func GetUsers(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		usersList, err := db.GetUsers()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot get user list: %v", err),
			})
		}

		return c.JSON(http.StatusOK, usersList)
	}
}

// GetUser handler returns a JSON object of single user
func GetUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		username := c.Param("username")

		if !isAdmin(c) && (username != currentUser(c)) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Manager cannot access other user data"})
		}

		userData, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}

		return c.JSON(http.StatusOK, userData)
	}
}

// Logout to log a user out
func Logout() echo.HandlerFunc {
	return func(c echo.Context) error {
		clearSession(c)
		return c.Redirect(http.StatusTemporaryRedirect, util.BasePath+"/login")
	}
}

// LoadProfile to load user information
func LoadProfile(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "profile.html", map[string]interface{}{
			"baseData": model.BaseData{Active: "profile", CurrentUser: currentUser(c), Admin: isAdmin(c)},
		})
	}
}

// UsersSettings handler
func UsersSettings(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "users_settings.html", map[string]interface{}{
			"baseData": model.BaseData{Active: "users-settings", CurrentUser: currentUser(c), Admin: isAdmin(c)},
		})
	}
}

// UpdateUser to update user information
func UpdateUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		username := data["username"].(string)
		password := data["password"].(string)
		previousUsername := data["previous_username"].(string)
		admin := data["admin"].(bool)

		if !isAdmin(c) && (previousUsername != currentUser(c)) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Manager cannot access other user data"})
		}

		if !isAdmin(c) {
			admin = false
		}

		user, err := db.GetUserByName(previousUsername)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, err.Error()})
		}

		if username == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		} else {
			user.Username = username
		}

		if username != previousUsername {
			_, err := db.GetUserByName(username)
			if err == nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "This username is taken"})
			}
		}

		if password != "" {
			hash, err := util.HashPassword(password)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
			}
			user.PasswordHash = hash
		}

		if previousUsername != currentUser(c) {
			user.Admin = admin
		}

		if err := db.DeleteUser(previousUsername); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		if err := db.SaveUser(user); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		log.Infof("Updated user information successfully")

		if previousUsername == currentUser(c) {
			setUser(c, user.Username, user.Admin)
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated user information successfully"})
	}
}

// CreateUser to create new user
func CreateUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		var user model.User
		username := data["username"].(string)
		password := data["password"].(string)
		admin := data["admin"].(bool)

		if username == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		} else {
			user.Username = username
		}

		{
			_, err := db.GetUserByName(username)
			if err == nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "This username is taken"})
			}
		}

		hash, err := util.HashPassword(password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		user.PasswordHash = hash

		user.Admin = admin

		if err := db.SaveUser(user); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		log.Infof("Created user successfully")

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Created user successfully"})
	}
}

// RemoveUser handler
func RemoveUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		username := data["username"].(string)

		if username == currentUser(c) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "User cannot delete itself"})
		}
		// delete user from database

		if err := db.DeleteUser(username); err != nil {
			log.Error("Cannot delete user: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot delete user from database"})
		}

		log.Infof("Removed user: %s", username)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "User removed"})
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
			"baseData":       model.BaseData{Active: "", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"clientDataList": clientDataList,
		})
	}
}

// GetClients handler return a JSON list of Wireguard client data
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

// GetClient handler returns a JSON object of Wireguard client data
func GetClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {

		clientID := c.Param("id")
		qrCodeIncludeFwMark := c.QueryParam("qrCodeIncludeFwMark")
		qrCodeSettings := model.QRCodeSettings{
			Enabled:       true,
			IncludeDNS:    true,
			IncludeFwMark: qrCodeIncludeFwMark == "true",
			IncludeMTU:    true,
		}

		clientData, err := db.GetClientByID(clientID, qrCodeSettings)
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

		// validate extra AllowedIPs
		if util.ValidateExtraAllowedIPs(client.ExtraAllowedIPs) == false {
			log.Warnf("Invalid Extra AllowedIPs input from user: %v", client.ExtraAllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Extra AllowedIPs must be in CIDR format"})
		}

		// gen ID
		guid := xid.New()
		client.ID = guid.String()

		// gen Wireguard key pair
		if client.PublicKey == "" {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				log.Error("Cannot generate wireguard key pair: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
			}
			client.PrivateKey = key.String()
			client.PublicKey = key.PublicKey().String()
		} else {
			_, err := wgtypes.ParseKey(client.PublicKey)
			if err != nil {
				log.Error("Cannot verify wireguard public key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot verify Wireguard public key"})
			}
			// check for duplicates
			clients, err := db.GetClients(false)
			if err != nil {
				log.Error("Cannot get clients for duplicate check")
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get clients for duplicate check"})
			}
			for _, other := range clients {
				if other.Client.PublicKey == client.PublicKey {
					log.Error("Duplicate Public Key")
					return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Duplicate Public Key"})
				}
			}

		}

		if client.PresharedKey == "" {
			presharedKey, err := wgtypes.GenerateKey()
			if err != nil {
				log.Error("Cannot generated preshared key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
					false, "Cannot generate Wireguard preshared key",
				})
			}
			client.PresharedKey = presharedKey.String()
		} else if client.PresharedKey == "-" {
			client.PresharedKey = ""
			log.Infof("skipped PresharedKey generation for user: %v", client.Name)
		} else {
			_, err := wgtypes.ParseKey(client.PresharedKey)
			if err != nil {
				log.Error("Cannot verify wireguard preshared key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot verify Wireguard preshared key"})
			}
		}
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

// EmailClient handler to send the configuration via email
func EmailClient(db store.IStore, mailer emailer.Emailer, emailSubject, emailContent string) echo.HandlerFunc {
	type clientIdEmailPayload struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}

	return func(c echo.Context) error {
		var payload clientIdEmailPayload
		c.Bind(&payload)
		// TODO validate email

		qrCodeSettings := model.QRCodeSettings{
			Enabled:       true,
			IncludeDNS:    true,
			IncludeFwMark: true,
			IncludeMTU:    true,
		}
		clientData, err := db.GetClientByID(payload.ID, qrCodeSettings)
		if err != nil {
			log.Errorf("Cannot generate client id %s config file for downloading: %v", payload.ID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		// build config
		server, _ := db.GetServer()
		globalSettings, _ := db.GetGlobalSettings()
		config := util.BuildClientConfig(*clientData.Client, server, globalSettings)

		cfgAtt := emailer.Attachment{"wg0.conf", []byte(config)}
		var attachments []emailer.Attachment
		if clientData.Client.PrivateKey != "" {
			qrdata, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(clientData.QRCode, "data:image/png;base64,"))
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "decoding: " + err.Error()})
			}
			qrAtt := emailer.Attachment{"wg.png", qrdata}
			attachments = []emailer.Attachment{cfgAtt, qrAtt}
		} else {
			attachments = []emailer.Attachment{cfgAtt}
		}
		err = mailer.Send(
			clientData.Client.Name,
			payload.Email,
			emailSubject,
			emailContent,
			attachments,
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
		clientData, err := db.GetClientByID(_client.ID, model.QRCodeSettings{Enabled: false})
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

		if util.ValidateExtraAllowedIPs(_client.ExtraAllowedIPs) == false {
			log.Warnf("Invalid Allowed IPs input from user: %v", _client.ExtraAllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Extra Allowed IPs must be in CIDR format"})
		}

		// map new data
		client.Name = _client.Name
		client.Email = _client.Email
		client.Enabled = _client.Enabled
		client.UseServerDNS = _client.UseServerDNS
		client.AllocatedIPs = _client.AllocatedIPs
		client.AllowedIPs = _client.AllowedIPs
		client.ExtraAllowedIPs = _client.ExtraAllowedIPs
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

		clientData, err := db.GetClientByID(clientID, model.QRCodeSettings{Enabled: false})
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, err.Error()})
		}

		client := *clientData.Client

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

		clientData, err := db.GetClientByID(clientID, model.QRCodeSettings{Enabled: false})
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
		c.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%s.conf", clientData.Client.Name))
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
			"baseData":        model.BaseData{Active: "wg-server", CurrentUser: currentUser(c), Admin: isAdmin(c)},
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
			"baseData":       model.BaseData{Active: "global-settings", CurrentUser: currentUser(c), Admin: isAdmin(c)},
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
		AllocatedIP       string
		Endpoint          string
	}

	type DeviceVM struct {
		Name  string
		Peers []PeerVM
	}
	return func(c echo.Context) error {

		wgClient, err := wgctrl.New()
		if err != nil {
			return c.Render(http.StatusInternalServerError, "status.html", map[string]interface{}{
				"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c), Admin: isAdmin(c)},
				"error":    err.Error(),
				"devices":  nil,
			})
		}

		devices, err := wgClient.Devices()
		if err != nil {
			return c.Render(http.StatusInternalServerError, "status.html", map[string]interface{}{
				"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c), Admin: isAdmin(c)},
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
					"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c), Admin: isAdmin(c)},
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
					var allocatedIPs string
					for _, ip := range devices[i].Peers[j].AllowedIPs {
						if len(allocatedIPs) > 0 {
							allocatedIPs += "</br>"
						}
						allocatedIPs += ip.String()
					}
					pVm := PeerVM{
						PublicKey:         devices[i].Peers[j].PublicKey.String(),
						ReceivedBytes:     devices[i].Peers[j].ReceiveBytes,
						TransmitBytes:     devices[i].Peers[j].TransmitBytes,
						LastHandshakeTime: devices[i].Peers[j].LastHandshakeTime,
						LastHandshakeRel:  time.Since(devices[i].Peers[j].LastHandshakeTime),
						AllocatedIP:       allocatedIPs,
						Endpoint:          devices[i].Peers[j].Endpoint.String(),
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
			"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c), Admin: isAdmin(c)},
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
			if strings.Contains(ip, ":") {
				suggestedIPs = append(suggestedIPs, fmt.Sprintf("%s/128", ip))
			} else {
				suggestedIPs = append(suggestedIPs, fmt.Sprintf("%s/32", ip))
			}
		}

		return c.JSON(http.StatusOK, suggestedIPs)
	}
}

// ApplyServerConfig handler to write config file and restart Wireguard server
func ApplyServerConfig(db store.IStore, tmplDir fs.FS) echo.HandlerFunc {
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

		users, err := db.GetUsers()
		if err != nil {
			log.Error("Cannot get users config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get users config"})
		}

		settings, err := db.GetGlobalSettings()
		if err != nil {
			log.Error("Cannot get global settings: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get global settings"})
		}

		// Write config file
		err = util.WriteWireGuardServerConfig(tmplDir, server, clients, users, settings)
		if err != nil {
			log.Error("Cannot apply server config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot apply server config: %v", err),
			})
		}

		err = util.UpdateHashes(db)
		if err != nil {
			log.Error("Cannot update hashes: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot update hashes: %v", err),
			})
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Applied server config successfully"})
	}
}


// GetHashesChanges handler returns if database hashes have changed
func GetHashesChanges(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		if util.HashesChanged(db) {
			return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Hashes changed"})
		} else {
			return c.JSON(http.StatusOK, jsonHTTPResponse{false, "Hashes not changed"})
		}
	}
}

// AboutPage handler
func AboutPage() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "about.html", map[string]interface{}{
			"baseData": model.BaseData{Active: "about", CurrentUser: currentUser(c), Admin: isAdmin(c)},
		})
	}
}
