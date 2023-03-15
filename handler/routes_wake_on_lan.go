package handler

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/sabhiram/go-wol/wol"
	"net"
	"net/http"
	"time"
)

type WakeOnLanHostSavePayload struct {
	Name          string `json:"name"`
	MacAddress    string `json:"mac_address"`
	OldMacAddress string `json:"old_mac_address"`
}

func createError(c echo.Context, err error, msg string) error {
	log.Error(msg, err)
	return c.JSON(
		http.StatusInternalServerError,
		jsonHTTPResponse{
			false,
			msg})
}

func GetWakeOnLanHosts(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var err error

		hosts, err := db.GetWakeOnLanHosts()
		if err != nil {
			return createError(c, err, fmt.Sprintf("wake_on_lan_hosts database error: %s", err))
		}

		err = c.Render(http.StatusOK, "wake_on_lan_hosts.html", map[string]interface{}{
			"baseData": model.BaseData{Active: "wake_on_lan_hosts", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"hosts":    hosts,
			"error":    "",
		})
		if err != nil {
			return createError(c, err, fmt.Sprintf("wake_on_lan_hosts.html render error: %s", err))
		}

		return nil
	}
}

func SaveWakeOnLanHost(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload WakeOnLanHostSavePayload
		err := c.Bind(&payload)
		if err != nil {
			log.Error("Wake On Host Save Payload Bind Error: ", err)
			return c.JSON(http.StatusInternalServerError, payload)
		}

		var host = model.WakeOnLanHost{
			MacAddress: payload.MacAddress,
			Name:       payload.Name,
		}
		if len(payload.OldMacAddress) != 0 { // Edit
			if payload.OldMacAddress != payload.MacAddress { // modified mac address
				oldHost, err := db.GetWakeOnLanHost(payload.OldMacAddress)
				if err != nil {
					return createError(c, err, fmt.Sprintf("Wake On Host Update Err: %s", err))
				}

				if payload.OldMacAddress != payload.MacAddress {
					existHost, _ := db.GetWakeOnLanHost(payload.MacAddress)
					if existHost != nil {
						return createError(c, nil, "Mac Address already exists.")
					}
				}

				err = db.DeleteWakeOnHostLanHost(payload.OldMacAddress)
				if err != nil {
					return createError(c, err, fmt.Sprintf("Wake On Host Update Err: %s", err))
				}
				host.LatestUsed = oldHost.LatestUsed
			}
			err = db.SaveWakeOnLanHost(host)
		} else { // new
			existHost, _ := db.GetWakeOnLanHost(payload.MacAddress)
			if existHost != nil {
				return createError(c, nil, "Mac Address already exists.")
			}

			err = db.SaveWakeOnLanHost(host)
		}

		if err != nil {
			return createError(c, err, fmt.Sprintf("Wake On Host Save Error: %s", err))
		}

		return c.JSON(http.StatusOK, host)
	}
}

func DeleteWakeOnHost(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var macAddress = c.Param("mac_address")
		var host, err = db.GetWakeOnLanHost(macAddress)

		if err != nil {
			log.Error("Wake On Host Delete Error: ", err)
			return createError(c, err, fmt.Sprintf("Wake On Host Delete Error: %s", macAddress))
		}

		err = db.DeleteWakeOnHost(*host)
		if err != nil {
			return createError(c, err, fmt.Sprintf("Wake On Host Delete Error: %s", macAddress))
		}

		return c.JSON(http.StatusOK, nil)
	}
}

func WakeOnHost(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		macAddress := c.Param("mac_address")
		host, err := db.GetWakeOnLanHost(macAddress)

		now := time.Now().UTC()
		host.LatestUsed = &now
		err = db.SaveWakeOnLanHost(*host)
		if err != nil {
			return createError(c, err, fmt.Sprintf("Latest Used Update Error: %s", macAddress))
		}

		magicPacket, err := wol.New(macAddress)
		if err != nil {
			return createError(c, err, fmt.Sprintf("Magic Packet Create Error: %s", macAddress))
		}

		bytes, err := magicPacket.Marshal()
		if err != nil {
			return createError(c, err, fmt.Sprintf("Magic Packet Bytestream Error: %s", macAddress))
		}

		udpAddr, err := net.ResolveUDPAddr("udp", "255.255.255.255:0")
		if err != nil {
			return createError(c, err, fmt.Sprintf("ResolveUDPAddr Error: %s", macAddress))
		}

		// Grab a UDP connection to send our packet of bytes.
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return err
		}
		defer func(conn *net.UDPConn) {
			err := conn.Close()
			if err != nil {
				log.Error(err)
			}
		}(conn)

		n, err := conn.Write(bytes)
		if err == nil && n != 102 {
			return createError(c, nil, fmt.Sprintf("magic packet sent was %d bytes (expected 102 bytes sent)", n))
		}
		if err != nil {
			return createError(c, err, fmt.Sprintf("Network Send Error: %s", macAddress))
		}

		return c.JSON(http.StatusOK, host.LatestUsed)
	}
}
