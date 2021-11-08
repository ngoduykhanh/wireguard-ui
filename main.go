package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/labstack/echo/v4"

	"github.com/ngoduykhanh/wireguard-ui/emailer"
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

const (
	defaultEmailSubject = "Your wireguard configuration"
	defaultEmailContent = `Hi,</br>
<p>in this email you can file your personal configuration for our wireguard server.</p>

<p>Best</p>
`
)

func init() {
	// command-line flags
	flagDisableLogin := flag.Bool("disable-login", false, "Disable login page. Turn off authentication.")
	flagBindAddress := flag.String("bind-address", "0.0.0.0:5000", "Address:Port to which the app will be bound.")
	flag.Parse()

	// update runtime config
	util.DisableLogin = *flagDisableLogin
	util.BindAddress = *flagBindAddress
	util.SendgridApiKey = os.Getenv("SENDGRID_API_KEY")
	util.EmailFrom = os.Getenv("EMAIL_FROM")
	util.EmailFromName = os.Getenv("EMAIL_FROM_NAME")
	util.SessionSecret = []byte(os.Getenv("SESSION_SECRET"))

	// print app information
	fmt.Println("Wireguard UI")
	fmt.Println("App Version\t:", appVersion)
	fmt.Println("Git Commit\t:", gitCommit)
	fmt.Println("Git Ref\t\t:", gitRef)
	fmt.Println("Build Time\t:", buildTime)
	fmt.Println("Git Repo\t:", "https://github.com/ngoduykhanh/wireguard-ui")
	fmt.Println("Authentication\t:", !util.DisableLogin)
	fmt.Println("Bind address\t:", util.BindAddress)

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
	app := router.New(tmplBox, extraData, util.SessionSecret)

	app.GET("/", handler.WireGuardClients(), handler.ValidSession)

	if !util.DisableLogin {
		app.GET("/login", handler.LoginPage())
		app.POST("/login", handler.Login())
	}

	sendmail := emailer.NewSendgridApiMail(util.SendgridApiKey, util.EmailFromName, util.EmailFrom)

	app.GET("/logout", handler.Logout(), handler.ValidSession)
	app.POST("/new-client", handler.NewClient(), handler.ValidSession)
	app.POST("/update-client", handler.UpdateClient(), handler.ValidSession)
	app.POST("/email-client", handler.EmailClient(sendmail, defaultEmailSubject, defaultEmailContent), handler.ValidSession)
	app.POST("/client/set-status", handler.SetClientStatus(), handler.ValidSession)
	app.POST("/remove-client", handler.RemoveClient(), handler.ValidSession)
	app.GET("/download", handler.DownloadClient(), handler.ValidSession)
	app.GET("/wg-server", handler.WireGuardServer(), handler.ValidSession)
	app.POST("wg-server/interfaces", handler.WireGuardServerInterfaces(), handler.ValidSession)
	app.POST("wg-server/keypair", handler.WireGuardServerKeyPair(), handler.ValidSession)
	app.GET("/global-settings", handler.GlobalSettings(), handler.ValidSession)
	app.POST("/global-settings", handler.GlobalSettingSubmit(), handler.ValidSession)
	app.GET("/api/clients", handler.GetClients(), handler.ValidSession)
	app.GET("/api/client/:id", handler.GetClient(), handler.ValidSession)
	app.GET("/api/machine-ips", handler.MachineIPAddresses(), handler.ValidSession)
	app.GET("/api/suggest-client-ips", handler.SuggestIPAllocation(), handler.ValidSession)
	app.GET("/api/apply-wg-config", handler.ApplyServerConfig(tmplBox), handler.ValidSession)

	// servers other static files
	app.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))

	app.Logger.Fatal(app.Start(util.BindAddress))
}
