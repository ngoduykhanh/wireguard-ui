package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/sdomino/scribble"
	"github.com/labstack/gommon/log"
	"github.com/rs/xid"
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

		clients := []model.Client{}
		for _, f := range records {
			client := model.Client{}
			if err := json.Unmarshal([]byte(f), &client); err != nil {
				log.Error("Cannot decode client json structure: ", err)
			}
			clients = append(clients, client)
		}

		return c.Render(http.StatusOK, "home.html", map[string]interface{}{
			"name": "Khanh",
			"clients": clients,
		})
	}
}

// NewClient handler
func NewClient() echo.HandlerFunc {
	return func (c echo.Context) error {
		client := new(model.Client)
		c.Bind(client)

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

		// write to the database
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
		}
		db.Write("clients", client.ID, client)
		log.Infof("Created wireguard client: %v", client)

		return c.JSON(http.StatusOK, client)	
	}
}

// RemoveClient handler
func RemoveClient() echo.HandlerFunc {
	return func (c echo.Context) error {
		client := new(model.Client)
		c.Bind(client)

		// delete from database
		dir := "./db"
		db, err := scribble.New(dir, nil)
		if err != nil {
			log.Error("Cannot initialize the database: ", err)
		}

		if err := db.Delete("clients", client.ID); err != nil {
			log.Error("Cannot delete wireguard client: ", err)
		}

		log.Infof("Removed wireguard client: %v", client)

		return c.JSON(http.StatusOK, "Client removed!")
	}
}