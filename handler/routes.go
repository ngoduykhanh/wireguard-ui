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

// Home handler
func Home() echo.HandlerFunc {
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
			png, err := qrcode.Encode(util.BuildClientConfig(client), qrcode.Medium, 256)
			if err != nil {
				log.Error("Cannot generate QRCode: ", err)
			}
			clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))

			// create the list of clients and their qrcode data
			clientDataList = append(clientDataList, clientData)
		}

		return c.Render(http.StatusOK, "home.html", map[string]interface{}{
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
			log.Warn("Invalid Allowed IPs input from user: %v", client.AllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Allowed IPs must be in CIDR format"})
		}

		// gen ID
		guid := xid.New()
		client.ID = guid.String()

		// gen Wireguard key pairs
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
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
