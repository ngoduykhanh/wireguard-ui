package main

import (
	"fmt"

	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/router"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

func main() {
	// initialize DB
	err := util.InitDB()
	if err != nil {
		fmt.Print("Cannot init database: ", err)
	}

	// register routes
	app := router.New()

	app.GET("/", handler.WireGuardClients())
	app.GET("/login", handler.LoginPage())
	app.POST("/new-client", handler.NewClient())
	app.POST("/client/set-status", handler.SetClientStatus())
	app.POST("/remove-client", handler.RemoveClient())
	app.GET("/wg-server", handler.WireGuardServer())
	app.POST("wg-server/interfaces", handler.WireGuardServerInterfaces())
	app.POST("wg-server/keypair", handler.WireGuardServerKeyPair())
	app.GET("/global-settings", handler.GlobalSettings())
	app.POST("/global-settings", handler.GlobalSettingSubmit())
	app.GET("/api/machine-ips", handler.MachineIPAddresses())
	app.GET("/api/suggest-client-ips", handler.SuggestIPAllocation())
	app.GET("/api/apply-wg-config", handler.ApplyServerConfig())
	app.Logger.Fatal(app.Start("127.0.0.1:5000"))
}
