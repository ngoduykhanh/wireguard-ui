package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/labstack/echo/v4"

	"github.com/ngoduykhanh/wireguard-ui/emailer"
	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/router"
	"github.com/ngoduykhanh/wireguard-ui/store/jsondb"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

var (
	// command-line banner information
	appVersion = "development"
	gitCommit  = "N/A"
	gitRef     = "N/A"
	buildTime  = fmt.Sprintf(time.Now().UTC().Format("01-02-2006 15:04:05"))
	// configuration variables
	flagDisableLogin   bool   = false
	flagBindAddress    string = "0.0.0.0:5000"
	flagSendgridApiKey string
	flagEmailFrom      string
	flagEmailFromName  string = "WireGuard UI"
	flagSessionSecret  string
)

const (
	defaultEmailSubject = "Your wireguard configuration"
	defaultEmailContent = `Hi,</br>
<p>In this email you can find your personal configuration for our wireguard server.</p>

<p>Best</p>
`
)

func init() {

	// command-line flags and env variables
	flag.BoolVar(&flagDisableLogin, "disable-login", util.LookupEnvOrBool("DISABLE_LOGIN", flagDisableLogin), "Disable authentication on the app. This is potentially dangerous.")
	flag.StringVar(&flagBindAddress, "bind-address", util.LookupEnvOrString("BIND_ADDRESS", flagBindAddress), "Address:Port to which the app will be bound.")
	flag.StringVar(&flagSendgridApiKey, "sendgrid-api-key", util.LookupEnvOrString("SENDGRID_API_KEY", flagSendgridApiKey), "Your sendgrid api key.")
	flag.StringVar(&flagEmailFrom, "email-from", util.LookupEnvOrString("EMAIL_FROM_ADDRESS", flagEmailFrom), "'From' email address.")
	flag.StringVar(&flagEmailFromName, "email-from-name", util.LookupEnvOrString("EMAIL_FROM_NAME", flagEmailFromName), "'From' email name.")
	flag.StringVar(&flagSessionSecret, "session-secret", util.LookupEnvOrString("SESSION_SECRET", flagSessionSecret), "The key used to encrypt session cookies.")
	flag.Parse()

	// update runtime config
	util.DisableLogin = flagDisableLogin
	util.BindAddress = flagBindAddress
	util.SendgridApiKey = flagSendgridApiKey
	util.EmailFrom = flagEmailFrom
	util.EmailFromName = flagEmailFromName
	util.SessionSecret = []byte(flagSessionSecret)

	// print app information
	fmt.Println("Wireguard UI")
	fmt.Println("App Version\t:", appVersion)
	fmt.Println("Git Commit\t:", gitCommit)
	fmt.Println("Git Ref\t\t:", gitRef)
	fmt.Println("Build Time\t:", buildTime)
	fmt.Println("Git Repo\t:", "https://github.com/ngoduykhanh/wireguard-ui")
	fmt.Println("Authentication\t:", !util.DisableLogin)
	fmt.Println("Bind address\t:", util.BindAddress)
	//fmt.Println("Sendgrid key\t:", util.SendgridApiKey)
	fmt.Println("Email from\t:", util.EmailFrom)
	fmt.Println("Email from name\t:", util.EmailFromName)
	//fmt.Println("Session secret\t:", util.SessionSecret)

}

func main() {
	db, err := jsondb.New("./db")
	if err != nil {
		panic(err)
	}
	if err := db.Init(); err != nil {
		panic(err)
	}
	// set app extra data
	extraData := make(map[string]string)
	extraData["appVersion"] = appVersion

	// create rice box for embedded template
	tmplBox := rice.MustFindBox("templates")

	// rice file server for assets. "assets" is the folder where the files come from.
	assetHandler := http.FileServer(rice.MustFindBox("assets").HTTPBox())

	// register routes
	app := router.New(tmplBox, extraData, util.SessionSecret)

	app.GET("/", handler.WireGuardClients(db), handler.ValidSession)

	if !util.DisableLogin {
		app.GET("/login", handler.LoginPage())
		app.POST("/login", handler.Login(db))
	}

	sendmail := emailer.NewSendgridApiMail(util.SendgridApiKey, util.EmailFromName, util.EmailFrom)

	app.GET("/_health", handler.Health())
	app.GET("/logout", handler.Logout(), handler.ValidSession)
	app.POST("/new-client", handler.NewClient(db), handler.ValidSession)
	app.POST("/update-client", handler.UpdateClient(db), handler.ValidSession)
	app.POST("/email-client", handler.EmailClient(db, sendmail, defaultEmailSubject, defaultEmailContent), handler.ValidSession)
	app.POST("/client/set-status", handler.SetClientStatus(db), handler.ValidSession)
	app.POST("/remove-client", handler.RemoveClient(db), handler.ValidSession)
	app.GET("/download", handler.DownloadClient(db), handler.ValidSession)
	app.GET("/wg-server", handler.WireGuardServer(db), handler.ValidSession)
	app.POST("wg-server/interfaces", handler.WireGuardServerInterfaces(db), handler.ValidSession)
	app.POST("wg-server/keypair", handler.WireGuardServerKeyPair(db), handler.ValidSession)
	app.GET("/global-settings", handler.GlobalSettings(db), handler.ValidSession)
	app.POST("/global-settings", handler.GlobalSettingSubmit(db), handler.ValidSession)
	app.GET("/status", handler.Status(db), handler.ValidSession)
	app.GET("/api/clients", handler.GetClients(db), handler.ValidSession)
	app.GET("/api/client/:id", handler.GetClient(db), handler.ValidSession)
	app.GET("/api/machine-ips", handler.MachineIPAddresses(), handler.ValidSession)
	app.GET("/api/suggest-client-ips", handler.SuggestIPAllocation(db), handler.ValidSession)
	app.GET("/api/apply-wg-config", handler.ApplyServerConfig(db, tmplBox), handler.ValidSession)

	// servers other static files
	app.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))

	app.Logger.Fatal(app.Start(util.BindAddress))
}
