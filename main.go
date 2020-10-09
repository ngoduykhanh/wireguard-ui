package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/router"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// command-line banner information
var (
	appVersion = "development"
	gitCommit  = "N/A"
	gitRef     = "N/A"
	buildTime  = fmt.Sprintf(time.Now().UTC().Format("01-02-2006 15:04:05"))
)

func init() {
	// command-line flags
	flagDisableLogin := flag.Bool("disable-login", false, "Disable login page. Turn off authentication.")
	flag.Parse()

	// update runtime config
	util.DisableLogin = *flagDisableLogin

	// print app information
	fmt.Println("Wireguard UI")
	fmt.Println("App Version\t:", appVersion)
	fmt.Println("Git Commit\t:", gitCommit)
	fmt.Println("Git Ref\t\t:", gitRef)
	fmt.Println("Build Time\t:", buildTime)
	fmt.Println("Git Repo\t:", "https://github.com/ngoduykhanh/wireguard-ui")
	fmt.Println("Authentication\t:", !util.DisableLogin)

	// initialize DB
	err := util.InitDB()
	if err != nil {
		fmt.Print("Cannot init database: ", err)
	}
}

func main() {
	// set app extra data
	extraData := make(map[string]string)
	extraData["appVersion"] = appVersion

	// create rice box for embedded template
	tmplBox := rice.MustFindBox("templates")

	// rice file server for assets. "assets" is the folder where the files come from.
	assetHandler := http.FileServer(rice.MustFindBox("assets").HTTPBox())

	// register routes
	app := router.New(tmplBox, extraData)

	app.GET("/", handler.WireGuardClients())

	if !util.DisableLogin {
		app.GET("/login", handler.LoginPage())
		app.POST("/login", handler.Login())
	}

	app.GET("/logout", handler.Logout())
	app.POST("/new-client", handler.NewClient())
	app.POST("/update-client", handler.UpdateClient())
	app.POST("/client/set-status", handler.SetClientStatus())
	app.POST("/remove-client", handler.RemoveClient())
	app.GET("/download", handler.DownloadClient())
	app.GET("/wg-server", handler.WireGuardServer())
	app.POST("wg-server/interfaces", handler.WireGuardServerInterfaces())
	app.POST("wg-server/keypair", handler.WireGuardServerKeyPair())
	app.GET("/global-settings", handler.GlobalSettings())
	app.POST("/global-settings", handler.GlobalSettingSubmit())
	app.GET("/api/clients", handler.GetClients())
	app.GET("/api/client/:id", handler.GetClient())
	app.GET("/api/machine-ips", handler.MachineIPAddresses())
	app.GET("/api/suggest-client-ips", handler.SuggestIPAllocation())
	app.GET("/api/apply-wg-config", handler.ApplyServerConfig(tmplBox))

	// servers other static files
	app.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))

	app.Logger.Fatal(app.Start("0.0.0.0:5000"))
}
