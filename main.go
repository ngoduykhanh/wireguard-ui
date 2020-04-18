package main

import (
	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/router"
)

func main() {
	app := router.New()

	app.GET("/", handler.Home())
	app.POST("/new-client", handler.NewClient())
	app.POST("/remove-client", handler.RemoveClient())

	app.Logger.Fatal(app.Start("127.0.0.1:5000"))
}
