package util

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/sdomino/scribble"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const dbPath = "./db"
const defaultServerAddress = "10.252.1.0/24"
const defaultServerPort = 51820

// DBConn to initialize the database connection
func DBConn() (*scribble.Driver, error) {
	db, err := scribble.New(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// InitDB to create the default database
func InitDB() error {
	var clientPath string = path.Join(dbPath, "clients")
	var serverPath string = path.Join(dbPath, "server")
	var serverInterfacePath string = path.Join(serverPath, "interfaces.json")
	var serverKeyPairPath string = path.Join(serverPath, "keypair.json")

	// create directories if they do not exist
	if _, err := os.Stat(clientPath); os.IsNotExist(err) {
		os.Mkdir(clientPath, os.ModePerm)
	}
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		os.Mkdir(serverPath, os.ModePerm)
	}

	// server's interface
	if _, err := os.Stat(serverInterfacePath); os.IsNotExist(err) {
		db, err := DBConn()
		if err != nil {
			return err
		}

		serverInterface := new(model.ServerInterface)
		serverInterface.Addresses = []string{defaultServerAddress}
		serverInterface.ListenPort = defaultServerPort
		serverInterface.UpdatedAt = time.Now().UTC()
		db.Write("server", "interfaces", serverInterface)
	}

	// server's key pair
	if _, err := os.Stat(serverKeyPairPath); os.IsNotExist(err) {
		db, err := DBConn()
		if err != nil {
			return err
		}

		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return scribble.ErrMissingCollection
		}
		serverKeyPair := new(model.ServerKeypair)
		serverKeyPair.PrivateKey = key.String()
		serverKeyPair.PublicKey = key.PublicKey().String()
		serverKeyPair.UpdatedAt = time.Now().UTC()
		db.Write("server", "keypair", serverKeyPair)
	}

	return nil
}

// GetGlobalSettings func to query global settings from the database
func GetGlobalSettings() (model.GlobalSetting, error) {
	settings := model.GlobalSetting{}

	db, err := DBConn()
	if err != nil {
		return settings, err
	}

	if err := db.Read("server", "global_settings", &settings); err != nil {
		return settings, err
	}

	return settings, nil
}

// GetServer func to query Server setting from the database
func GetServer() (model.Server, error) {
	server := model.Server{}

	db, err := DBConn()
	if err != nil {
		return server, err
	}

	// read server interface information
	serverInterface := model.ServerInterface{}
	if err := db.Read("server", "interfaces", &serverInterface); err != nil {
		return server, err
	}

	// read server key pair information
	serverKeyPair := model.ServerKeypair{}
	if err := db.Read("server", "keypair", &serverKeyPair); err != nil {
		return server, err
	}

	// create Server object and return
	server.Interface = &serverInterface
	server.KeyPair = &serverKeyPair
	return server, nil
}

// GetClients to get all clients from the database
func GetClients(hasQRCode bool) ([]model.ClientData, error) {
	clients := []model.ClientData{}

	db, err := DBConn()
	if err != nil {
		return clients, err
	}

	// read all client json file in "clients" directory
	records, err := db.ReadAll("clients")
	if err != nil {
		return clients, err
	}

	// build the ClientData list
	for _, f := range records {
		client := model.Client{}
		clientData := model.ClientData{}

		// get client info
		if err := json.Unmarshal([]byte(f), &client); err != nil {
			return clients, fmt.Errorf("Cannot decode client json structure: %v", err)
		}

		// generate client qrcode image in base64
		if hasQRCode {
			server, _ := GetServer()
			globalSettings, _ := GetGlobalSettings()

			png, _ := qrcode.Encode(BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
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
