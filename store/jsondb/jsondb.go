package jsondb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
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
	var clientPath string = path.Join(o.dbPath, "clients")
	var serverPath string = path.Join(o.dbPath, "server")
	var wakeOnLanHostsPath string = path.Join(o.dbPath, "wake_on_lan_hosts")
	var serverInterfacePath string = path.Join(serverPath, "interfaces.json")
	var serverKeyPairPath string = path.Join(serverPath, "keypair.json")
	var globalSettingPath string = path.Join(serverPath, "global_settings.json")
	var userPath string = path.Join(serverPath, "users.json")
	// create directories if they do not exist
	if _, err := os.Stat(clientPath); os.IsNotExist(err) {
		os.MkdirAll(clientPath, os.ModePerm)
	}
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		os.MkdirAll(serverPath, os.ModePerm)
	}
	if _, err := os.Stat(wakeOnLanHostsPath); os.IsNotExist(err) {
		os.MkdirAll(wakeOnLanHostsPath, os.ModePerm)
	}

	// server's interface
	if _, err := os.Stat(serverInterfacePath); os.IsNotExist(err) {
		serverInterface := new(model.ServerInterface)
		serverInterface.Addresses = []string{util.DefaultServerAddress}
		serverInterface.ListenPort = util.DefaultServerPort
		serverInterface.UpdatedAt = time.Now().UTC()
		o.conn.Write("server", "interfaces", serverInterface)
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
	}

	// global settings
	if _, err := os.Stat(globalSettingPath); os.IsNotExist(err) {

		publicInterface, err := util.GetPublicIP()
		if err != nil {
			return err
		}

		globalSetting := new(model.GlobalSetting)
		globalSetting.EndpointAddress = publicInterface.IPAddress
		globalSetting.DNSServers = []string{util.DefaultDNS}
		globalSetting.MTU = util.DefaultMTU
		globalSetting.PersistentKeepalive = util.DefaultPersistentKeepalive
		globalSetting.ConfigFilePath = util.DefaultConfigFilePath
		globalSetting.UpdatedAt = time.Now().UTC()
		o.conn.Write("server", "global_settings", globalSetting)
	}

	// user info
	if _, err := os.Stat(userPath); os.IsNotExist(err) {
		user := new(model.User)
		user.Username = util.GetCredVar(util.UsernameEnvVar, util.DefaultUsername)
		user.Password = util.GetCredVar(util.PasswordEnvVar, util.DefaultPassword)
		o.conn.Write("server", "users", user)
	}

	return nil
}

// GetUser func to query user info from the database
func (o *JsonDB) GetUser() (model.User, error) {
	user := model.User{}
	return user, o.conn.Read("server", "users", &user)
}

// GetGlobalSettings func to query global settings from the database
func (o *JsonDB) GetGlobalSettings() (model.GlobalSetting, error) {
	settings := model.GlobalSetting{}
	return settings, o.conn.Read("server", "global_settings", &settings)
}

// GetServer func to query Server setting from the database
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

	// read all client json file in "clients" directory
	records, err := o.conn.ReadAll("clients")
	if err != nil {
		return clients, err
	}

	// build the ClientData list
	for _, f := range records {
		client := model.Client{}
		clientData := model.ClientData{}

		// get client info
		if err := json.Unmarshal([]byte(f), &client); err != nil {
			return clients, fmt.Errorf("cannot decode client json structure: %v", err)
		}

		// generate client qrcode image in base64
		if hasQRCode && client.PrivateKey != "" {
			server, _ := o.GetServer()
			globalSettings, _ := o.GetGlobalSettings()

			png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
			if err == nil {
				clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
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

func (o *JsonDB) GetClientByID(clientID string, hasQRCode bool) (model.ClientData, error) {
	client := model.Client{}
	clientData := model.ClientData{}

	// read client information
	if err := o.conn.Read("clients", clientID, &client); err != nil {
		return clientData, err
	}

	// generate client qrcode image in base64
	if hasQRCode && client.PrivateKey != "" {
		server, _ := o.GetServer()
		globalSettings, _ := o.GetGlobalSettings()

		png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
		if err == nil {
			clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
		} else {
			fmt.Print("Cannot generate QR code: ", err)
		}
	}

	clientData.Client = &client

	return clientData, nil
}

func (o *JsonDB) SaveClient(client model.Client) error {
	return o.conn.Write("clients", client.ID, client)
}

func (o *JsonDB) DeleteClient(clientID string) error {
	return o.conn.Delete("clients", clientID)
}

func (o *JsonDB) SaveServerInterface(serverInterface model.ServerInterface) error {
	return o.conn.Write("server", "interfaces", serverInterface)
}

func (o *JsonDB) SaveServerKeyPair(serverKeyPair model.ServerKeypair) error {
	return o.conn.Write("server", "keypair", serverKeyPair)
}

func (o *JsonDB) SaveGlobalSettings(globalSettings model.GlobalSetting) error {
	return o.conn.Write("server", "global_settings", globalSettings)
}
