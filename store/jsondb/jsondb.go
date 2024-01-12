package jsondb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/sdomino/scribble"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

type JsonDB struct {
	conn   *scribble.Driver
	dbPath string
}

// New returns a new pointer JsonDB
func New(dbPath string) (*JsonDB, error) {
	conn, err := scribble.New(dbPath, nil)
	if err != nil {
		return nil, err
	}
	ans := JsonDB{
		conn:   conn,
		dbPath: dbPath,
	}
	return &ans, nil
}

func (o *JsonDB) Init() error {
	var clientPath = path.Join(o.dbPath, "clients")
	var serverPath = path.Join(o.dbPath, "server")
	var userPath = path.Join(o.dbPath, "users")
	var wakeOnLanHostsPath = path.Join(o.dbPath, "wake_on_lan_hosts")
	var serverInterfacePath = path.Join(serverPath, "interfaces.json")
	var serverKeyPairPath = path.Join(serverPath, "keypair.json")
	var globalSettingPath = path.Join(serverPath, "global_settings.json")
	var hashesPath = path.Join(serverPath, "hashes.json")

	// create directories if they do not exist
	if _, err := os.Stat(clientPath); os.IsNotExist(err) {
		os.MkdirAll(clientPath, os.ModePerm)
	}
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		os.MkdirAll(serverPath, os.ModePerm)
	}
	if _, err := os.Stat(userPath); os.IsNotExist(err) {
		os.MkdirAll(userPath, os.ModePerm)
	}
	if _, err := os.Stat(wakeOnLanHostsPath); os.IsNotExist(err) {
		os.MkdirAll(wakeOnLanHostsPath, os.ModePerm)
	}

	// server's interface
	if _, err := os.Stat(serverInterfacePath); os.IsNotExist(err) {
		serverInterface := new(model.ServerInterface)
		serverInterface.Addresses = util.LookupEnvOrStrings(util.ServerAddressesEnvVar, []string{util.DefaultServerAddress})
		serverInterface.ListenPort = util.LookupEnvOrInt(util.ServerListenPortEnvVar, util.DefaultServerPort)
		serverInterface.PostUp = util.LookupEnvOrString(util.ServerPostUpScriptEnvVar, "")
		serverInterface.PostDown = util.LookupEnvOrString(util.ServerPostDownScriptEnvVar, "")
		serverInterface.UpdatedAt = time.Now().UTC()
		o.conn.Write("server", "interfaces", serverInterface)
		err := util.ManagePerms(serverInterfacePath)
		if err != nil {
			return err
		}
	}

	// server's key pair
	if _, err := os.Stat(serverKeyPairPath); os.IsNotExist(err) {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return scribble.ErrMissingCollection
		}
		serverKeyPair := new(model.ServerKeypair)
		serverKeyPair.PrivateKey = key.String()
		serverKeyPair.PublicKey = key.PublicKey().String()
		serverKeyPair.UpdatedAt = time.Now().UTC()
		o.conn.Write("server", "keypair", serverKeyPair)
		err = util.ManagePerms(serverKeyPairPath)
		if err != nil {
			return err
		}
	}

	// global settings
	if _, err := os.Stat(globalSettingPath); os.IsNotExist(err) {
		endpointAddress := util.LookupEnvOrString(util.EndpointAddressEnvVar, "")
		if endpointAddress == "" {
			// automatically find an external IP address
			publicInterface, err := util.GetPublicIP()
			if err != nil {
				return err
			}
			endpointAddress = publicInterface.IPAddress
		}

		globalSetting := new(model.GlobalSetting)
		globalSetting.EndpointAddress = endpointAddress
		globalSetting.DNSServers = util.LookupEnvOrStrings(util.DNSEnvVar, []string{util.DefaultDNS})
		globalSetting.MTU = util.LookupEnvOrInt(util.MTUEnvVar, util.DefaultMTU)
		globalSetting.PersistentKeepalive = util.LookupEnvOrInt(util.PersistentKeepaliveEnvVar, util.DefaultPersistentKeepalive)
		globalSetting.FirewallMark = util.LookupEnvOrString(util.FirewallMarkEnvVar, util.DefaultFirewallMark)
		globalSetting.Table = util.LookupEnvOrString(util.TableEnvVar, util.DefaultTable)
		globalSetting.ConfigFilePath = util.LookupEnvOrString(util.ConfigFilePathEnvVar, util.DefaultConfigFilePath)
		globalSetting.UpdatedAt = time.Now().UTC()
		o.conn.Write("server", "global_settings", globalSetting)
		err := util.ManagePerms(globalSettingPath)
		if err != nil {
			return err
		}
	}

	// hashes
	if _, err := os.Stat(hashesPath); os.IsNotExist(err) {
		clientServerHashes := new(model.ClientServerHashes)
		clientServerHashes.Client = "none"
		clientServerHashes.Server = "none"
		o.conn.Write("server", "hashes", clientServerHashes)
		err := util.ManagePerms(hashesPath)
		if err != nil {
			return err
		}
	}

	// user info
	results, err := o.conn.ReadAll("users")
	if err != nil || len(results) < 1 {
		user := new(model.User)
		user.Username = util.LookupEnvOrString(util.UsernameEnvVar, util.DefaultUsername)
		user.Admin = util.DefaultIsAdmin
		user.PasswordHash = util.LookupEnvOrString(util.PasswordHashEnvVar, "")
		if user.PasswordHash == "" {
			user.PasswordHash = util.LookupEnvOrFile(util.PasswordHashFileEnvVar, "")
			if user.PasswordHash == "" {
				plaintext := util.LookupEnvOrString(util.PasswordEnvVar, util.DefaultPassword)
				if plaintext == util.DefaultPassword {
					plaintext = util.LookupEnvOrFile(util.PasswordFileEnvVar, util.DefaultPassword)
				}
				hash, err := util.HashPassword(plaintext)
				if err != nil {
					return err
				}
				user.PasswordHash = hash
			}
		}

		o.conn.Write("users", user.Username, user)
		results, _ = o.conn.ReadAll("users")
		err = util.ManagePerms(path.Join(path.Join(o.dbPath, "users"), user.Username+".json"))
		if err != nil {
			return err
		}
	}

	// init cache
	for _, i := range results {
		user := model.User{}

		if err := json.Unmarshal([]byte(i), &user); err == nil {
			util.DBUsersToCRC32[user.Username] = util.GetDBUserCRC32(user)
		}
	}

	clients, err := o.GetClients(false)
	if err != nil {
		return nil
	}
	for _, cl := range clients {
		client := cl.Client
		if client.Enabled && len(client.TgUserid) > 0 {
			if userid, err := strconv.ParseInt(client.TgUserid, 10, 64); err == nil {
				util.UpdateTgToClientID(userid, client.ID)
			}
		}
	}

	return nil
}

// GetUsers func to get all users from the database
func (o *JsonDB) GetUsers() ([]model.User, error) {
	var users []model.User
	results, err := o.conn.ReadAll("users")
	if err != nil {
		return users, err
	}
	for _, i := range results {
		user := model.User{}

		if err := json.Unmarshal(i, &user); err != nil {
			return users, fmt.Errorf("cannot decode user json structure: %v", err)
		}
		users = append(users, user)
	}
	return users, err
}

// GetUserByName func to get single user from the database
func (o *JsonDB) GetUserByName(username string) (model.User, error) {
	user := model.User{}

	if err := o.conn.Read("users", username, &user); err != nil {
		return user, err
	}

	return user, nil
}

// SaveUser func to save user in the database
func (o *JsonDB) SaveUser(user model.User) error {
	userPath := path.Join(path.Join(o.dbPath, "users"), user.Username+".json")
	output := o.conn.Write("users", user.Username, user)
	err := util.ManagePerms(userPath)
	if err != nil {
		return err
	}
	util.DBUsersToCRC32[user.Username] = util.GetDBUserCRC32(user)
	return output
}

// DeleteUser func to remove user from the database
func (o *JsonDB) DeleteUser(username string) error {
	delete(util.DBUsersToCRC32, username)
	return o.conn.Delete("users", username)
}

// GetGlobalSettings func to query global settings from the database
func (o *JsonDB) GetGlobalSettings() (model.GlobalSetting, error) {
	settings := model.GlobalSetting{}
	return settings, o.conn.Read("server", "global_settings", &settings)
}

// GetServer func to query Server settings from the database
func (o *JsonDB) GetServer() (model.Server, error) {
	server := model.Server{}
	// read server interface information
	serverInterface := model.ServerInterface{}
	if err := o.conn.Read("server", "interfaces", &serverInterface); err != nil {
		return server, err
	}

	// read server key pair information
	serverKeyPair := model.ServerKeypair{}
	if err := o.conn.Read("server", "keypair", &serverKeyPair); err != nil {
		return server, err
	}

	// create Server object and return
	server.Interface = &serverInterface
	server.KeyPair = &serverKeyPair
	return server, nil
}

func (o *JsonDB) GetClients(hasQRCode bool) ([]model.ClientData, error) {
	var clients []model.ClientData

	// read all client json files in "clients" directory
	records, err := o.conn.ReadAll("clients")
	if err != nil {
		return clients, err
	}

	// build the ClientData list
	for _, f := range records {
		client := model.Client{}
		clientData := model.ClientData{}

		// get client info
		if err := json.Unmarshal(f, &client); err != nil {
			return clients, fmt.Errorf("cannot decode client json structure: %v", err)
		}

		// generate client qrcode image in base64
		if hasQRCode && client.PrivateKey != "" {
			server, _ := o.GetServer()
			globalSettings, _ := o.GetGlobalSettings()

			png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
			if err == nil {
				clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
			} else {
				fmt.Print("Cannot generate QR code: ", err)
			}
		}

		// create the list of clients and their qrcode data
		clientData.Client = &client
		clients = append(clients, clientData)
	}

	return clients, nil
}

func (o *JsonDB) GetClientByID(clientID string, qrCodeSettings model.QRCodeSettings) (model.ClientData, error) {
	client := model.Client{}
	clientData := model.ClientData{}

	// read client information
	if err := o.conn.Read("clients", clientID, &client); err != nil {
		return clientData, err
	}

	// generate client qrcode image in base64
	if qrCodeSettings.Enabled && client.PrivateKey != "" {
		server, _ := o.GetServer()
		globalSettings, _ := o.GetGlobalSettings()
		client := client
		if !qrCodeSettings.IncludeDNS {
			globalSettings.DNSServers = []string{}
		}
		if !qrCodeSettings.IncludeMTU {
			globalSettings.MTU = 0
		}

		png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
		if err == nil {
			clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
		} else {
			fmt.Print("Cannot generate QR code: ", err)
		}
	}

	clientData.Client = &client

	return clientData, nil
}

func (o *JsonDB) SaveClient(client model.Client) error {
	clientPath := path.Join(path.Join(o.dbPath, "clients"), client.ID+".json")
	output := o.conn.Write("clients", client.ID, client)
	if output == nil {
		if client.Enabled && len(client.TgUserid) > 0 {
			if userid, err := strconv.ParseInt(client.TgUserid, 10, 64); err == nil {
				util.UpdateTgToClientID(userid, client.ID)
			}
		} else {
			util.RemoveTgToClientID(client.ID)
		}
	} else {
		util.RemoveTgToClientID(client.ID)
	}
	err := util.ManagePerms(clientPath)
	if err != nil {
		return err
	}
	return output
}

func (o *JsonDB) DeleteClient(clientID string) error {
	util.RemoveTgToClientID(clientID)
	return o.conn.Delete("clients", clientID)
}

func (o *JsonDB) SaveServerInterface(serverInterface model.ServerInterface) error {
	serverInterfacePath := path.Join(path.Join(o.dbPath, "server"), "interfaces.json")
	output := o.conn.Write("server", "interfaces", serverInterface)
	err := util.ManagePerms(serverInterfacePath)
	if err != nil {
		return err
	}
	return output
}

func (o *JsonDB) SaveServerKeyPair(serverKeyPair model.ServerKeypair) error {
	serverKeyPairPath := path.Join(path.Join(o.dbPath, "server"), "keypair.json")
	output := o.conn.Write("server", "keypair", serverKeyPair)
	err := util.ManagePerms(serverKeyPairPath)
	if err != nil {
		return err
	}
	return output
}

func (o *JsonDB) SaveGlobalSettings(globalSettings model.GlobalSetting) error {
	globalSettingsPath := path.Join(path.Join(o.dbPath, "server"), "global_settings.json")
	output := o.conn.Write("server", "global_settings", globalSettings)
	err := util.ManagePerms(globalSettingsPath)
	if err != nil {
		return err
	}
	return output
}

func (o *JsonDB) GetPath() string {
	return o.dbPath
}

func (o *JsonDB) GetHashes() (model.ClientServerHashes, error) {
	hashes := model.ClientServerHashes{}
	return hashes, o.conn.Read("server", "hashes", &hashes)
}

func (o *JsonDB) SaveHashes(hashes model.ClientServerHashes) error {
	hashesPath := path.Join(path.Join(o.dbPath, "server"), "hashes.json")
	output := o.conn.Write("server", "hashes", hashes)
	err := util.ManagePerms(hashesPath)
	if err != nil {
		return err
	}
	return output
}
