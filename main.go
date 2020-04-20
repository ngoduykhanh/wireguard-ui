package main

import (
	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/router"
)

func main() {
	app := router.New()

	app.GET("/", handler.WireGuardClients())
	app.POST("/new-client", handler.NewClient())
	app.POST("/remove-client", handler.RemoveClient())
	app.GET("/wg-server", handler.WireGuardServer())
	app.POST("wg-server/interfaces", handler.WireGuardServerInterfaces())
	app.POST("wg-server/keypair", handler.WireGuardServerKeyPair())
	app.GET("/global-settings", handler.GlobalSettings())
	app.POST("/global-settings", handler.GlobalSettingSubmit())
	app.GET("/api/machine-ips", handler.MachineIPAddresses())
	app.GET("/api/suggest-client-ips", handler.SuggestIPAllocation())
	app.Logger.Fatal(app.Start("127.0.0.1:5000"))
}
