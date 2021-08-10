package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/labstack/echo/v4"

	"github.com/ngoduykhanh/wireguard-ui/emailer"
	"github.com/ngoduykhanh/wireguard-ui/handler"
	"github.com/ngoduykhanh/wireguard-ui/router"
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
<p>in this email you can file your personal configuration for our wireguard server.</p>

<p>Best</p>
`
)

func init() {

	// command-line flags and env variables
	flag.BoolVar(&flagDisableLogin, "disable-login", LookupEnvOrBool("DISABLE_LOGIN", flagDisableLogin), "Disable login page. Turn off authentication.")
	flag.StringVar(&flagBindAddress, "bind-address", LookupEnvOrString("BIND_ADDRESS", flagBindAddress), "Address:Port to which the app will be bound.")
	flag.StringVar(&flagSendgridApiKey, "sendgrid-api-key", LookupEnvOrString("SENDGRID_API_KEY", flagSendgridApiKey), "Your sendgrid api key.")
	flag.StringVar(&flagEmailFrom, "email-from", LookupEnvOrString("EMAIL_FROM_ADDRESS", flagEmailFrom), "'From' email address.")
	flag.StringVar(&flagEmailFromName, "email-from-name", LookupEnvOrString("EMAIL_FROM_NAME", flagEmailFromName), "'From' email name.")
	flag.StringVar(&flagSessionSecret, "session-secret", LookupEnvOrString("SESSION_SECRET", flagSessionSecret), "The key used to encrypt session cookies.")
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

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func LookupEnvOrBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.ParseBool(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "LookupEnvOrInt[%s]: %v\n", key, err)
		}
		return v
	}
	return defaultVal
}

func LookupEnvOrInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "LookupEnvOrInt[%s]: %v\n", key, err)
		}
		return v
	}
	return defaultVal
}
