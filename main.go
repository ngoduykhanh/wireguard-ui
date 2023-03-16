package main

import (
	"embed"
	"flag"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"io/fs"
	"net/http"
	"os"
	"time"

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
	flagSmtpHostname   string = "127.0.0.1"
	flagSmtpPort       int    = 25
	flagSmtpUsername   string
	flagSmtpPassword   string
	flagSmtpAuthType   string = "NONE"
	flagSmtpNoTLSCheck bool   = false
	flagSmtpEncryption string = "STARTTLS"
	flagSendgridApiKey string
	flagEmailFrom      string
	flagEmailFromName  string = "WireGuard UI"
	flagSessionSecret  string
	flagWgConfTemplate string
	flagBasePath       string
)

const (
	defaultEmailSubject = "Your wireguard configuration"
	defaultEmailContent = `Hi,</br>
<p>In this email you can find your personal configuration for our wireguard server.</p>

<p>Best</p>
`
)

// embed the "templates" directory
//
//go:embed templates/*
var embeddedTemplates embed.FS

// embed the "assets" directory
//
//go:embed assets/*
var embeddedAssets embed.FS

func init() {

	// command-line flags and env variables
	flag.BoolVar(&flagDisableLogin, "disable-login", util.LookupEnvOrBool("DISABLE_LOGIN", flagDisableLogin), "Disable authentication on the app. This is potentially dangerous.")
	flag.StringVar(&flagBindAddress, "bind-address", util.LookupEnvOrString("BIND_ADDRESS", flagBindAddress), "Address:Port to which the app will be bound.")
	flag.StringVar(&flagSmtpHostname, "smtp-hostname", util.LookupEnvOrString("SMTP_HOSTNAME", flagSmtpHostname), "SMTP Hostname")
	flag.IntVar(&flagSmtpPort, "smtp-port", util.LookupEnvOrInt("SMTP_PORT", flagSmtpPort), "SMTP Port")
	flag.StringVar(&flagSmtpUsername, "smtp-username", util.LookupEnvOrString("SMTP_USERNAME", flagSmtpUsername), "SMTP Username")
	flag.StringVar(&flagSmtpPassword, "smtp-password", util.LookupEnvOrString("SMTP_PASSWORD", flagSmtpPassword), "SMTP Password")
	flag.BoolVar(&flagSmtpNoTLSCheck, "smtp-no-tls-check", util.LookupEnvOrBool("SMTP_NO_TLS_CHECK", flagSmtpNoTLSCheck), "Disable TLS verification for SMTP. This is potentially dangerous.")
	flag.StringVar(&flagSmtpEncryption, "smtp-encryption", util.LookupEnvOrString("SMTP_ENCRYPTION", flagSmtpEncryption), "SMTP Encryption : NONE, SSL, SSLTLS, TLS or STARTTLS (by default)")
	flag.StringVar(&flagSmtpAuthType, "smtp-auth-type", util.LookupEnvOrString("SMTP_AUTH_TYPE", flagSmtpAuthType), "SMTP Auth Type : PLAIN, LOGIN or NONE.")
	flag.StringVar(&flagSendgridApiKey, "sendgrid-api-key", util.LookupEnvOrString("SENDGRID_API_KEY", flagSendgridApiKey), "Your sendgrid api key.")
	flag.StringVar(&flagEmailFrom, "email-from", util.LookupEnvOrString("EMAIL_FROM_ADDRESS", flagEmailFrom), "'From' email address.")
	flag.StringVar(&flagEmailFromName, "email-from-name", util.LookupEnvOrString("EMAIL_FROM_NAME", flagEmailFromName), "'From' email name.")
	flag.StringVar(&flagSessionSecret, "session-secret", util.LookupEnvOrString("SESSION_SECRET", flagSessionSecret), "The key used to encrypt session cookies.")
	flag.StringVar(&flagWgConfTemplate, "wg-conf-template", util.LookupEnvOrString("WG_CONF_TEMPLATE", flagWgConfTemplate), "Path to custom wg.conf template.")
	flag.StringVar(&flagBasePath, "base-path", util.LookupEnvOrString("BASE_PATH", flagBasePath), "The base path of the URL")
	flag.Parse()

	// update runtime config
	util.DisableLogin = flagDisableLogin
	util.BindAddress = flagBindAddress
	util.SmtpHostname = flagSmtpHostname
	util.SmtpPort = flagSmtpPort
	util.SmtpUsername = flagSmtpUsername
	util.SmtpPassword = flagSmtpPassword
	util.SmtpAuthType = flagSmtpAuthType
	util.SmtpNoTLSCheck = flagSmtpNoTLSCheck
	util.SmtpEncryption = flagSmtpEncryption
	util.SendgridApiKey = flagSendgridApiKey
	util.EmailFrom = flagEmailFrom
	util.EmailFromName = flagEmailFromName
	util.SessionSecret = []byte(flagSessionSecret)
	util.WgConfTemplate = flagWgConfTemplate
	util.BasePath = util.ParseBasePath(flagBasePath)

	// print only if log level is INFO or lower
	if lvl, _ := util.ParseLogLevel(util.LookupEnvOrString(util.LogLevel, "INFO")); lvl <= log.INFO {
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
		fmt.Println("Custom wg.conf\t:", util.WgConfTemplate)
		fmt.Println("Base path\t:", util.BasePath+"/")
	}
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
	extraData["gitCommit"] = gitCommit
	extraData["basePath"] = util.BasePath

	// strip the "templates/" prefix from the embedded directory so files can be read by their direct name (e.g.
	// "base.html" instead of "templates/base.html")
	tmplDir, _ := fs.Sub(fs.FS(embeddedTemplates), "templates")

	// create the wireguard config on start, if it doesn't exist
	initServerConfig(db, tmplDir)

	// register routes
	app := router.New(tmplDir, extraData, util.SessionSecret)

	app.GET(util.BasePath, handler.WireGuardClients(db), handler.ValidSession)

	if !util.DisableLogin {
		app.GET(util.BasePath+"/login", handler.LoginPage())
		app.POST(util.BasePath+"/login", handler.Login(db))
		app.GET(util.BasePath+"/logout", handler.Logout(), handler.ValidSession)
		app.GET(util.BasePath+"/profile", handler.LoadProfile(db), handler.ValidSession)
		app.GET(util.BasePath+"/users-settings", handler.UsersSettings(db), handler.ValidSession, handler.NeedsAdmin)
		app.POST(util.BasePath+"/update-user", handler.UpdateUser(db), handler.ValidSession)
		app.POST(util.BasePath+"/create-user", handler.CreateUser(db), handler.ValidSession, handler.NeedsAdmin)
		app.POST(util.BasePath+"/remove-user", handler.RemoveUser(db), handler.ValidSession, handler.NeedsAdmin)
		app.GET(util.BasePath+"/getusers", handler.GetUsers(db), handler.ValidSession, handler.NeedsAdmin)
		app.GET(util.BasePath+"/api/user/:username", handler.GetUser(db), handler.ValidSession)
	}

	var sendmail emailer.Emailer
	if util.SendgridApiKey != "" {
		sendmail = emailer.NewSendgridApiMail(util.SendgridApiKey, util.EmailFromName, util.EmailFrom)
	} else {
		sendmail = emailer.NewSmtpMail(util.SmtpHostname, util.SmtpPort, util.SmtpUsername, util.SmtpPassword, util.SmtpNoTLSCheck, util.SmtpAuthType, util.EmailFromName, util.EmailFrom, util.SmtpEncryption)
	}

	app.GET(util.BasePath+"/test-hash", handler.GetHashesChanges(db), handler.ValidSession)
	app.GET(util.BasePath+"/about", handler.AboutPage())
	app.GET(util.BasePath+"/_health", handler.Health())
	app.GET(util.BasePath+"/favicon", handler.Favicon())
	app.POST(util.BasePath+"/new-client", handler.NewClient(db), handler.ValidSession, handler.ContentTypeJson)
	app.POST(util.BasePath+"/update-client", handler.UpdateClient(db), handler.ValidSession, handler.ContentTypeJson)
	app.POST(util.BasePath+"/email-client", handler.EmailClient(db, sendmail, defaultEmailSubject, defaultEmailContent), handler.ValidSession, handler.ContentTypeJson)
	app.POST(util.BasePath+"/client/set-status", handler.SetClientStatus(db), handler.ValidSession, handler.ContentTypeJson)
	app.POST(util.BasePath+"/remove-client", handler.RemoveClient(db), handler.ValidSession, handler.ContentTypeJson)
	app.GET(util.BasePath+"/download", handler.DownloadClient(db), handler.ValidSession)
	app.GET(util.BasePath+"/wg-server", handler.WireGuardServer(db), handler.ValidSession, handler.NeedsAdmin)
	app.POST(util.BasePath+"/wg-server/interfaces", handler.WireGuardServerInterfaces(db), handler.ValidSession, handler.ContentTypeJson, handler.NeedsAdmin)
	app.POST(util.BasePath+"/wg-server/keypair", handler.WireGuardServerKeyPair(db), handler.ValidSession, handler.ContentTypeJson, handler.NeedsAdmin)
	app.GET(util.BasePath+"/global-settings", handler.GlobalSettings(db), handler.ValidSession, handler.NeedsAdmin)
	app.POST(util.BasePath+"/global-settings", handler.GlobalSettingSubmit(db), handler.ValidSession, handler.ContentTypeJson, handler.NeedsAdmin)
	app.GET(util.BasePath+"/status", handler.Status(db), handler.ValidSession)
	app.GET(util.BasePath+"/api/clients", handler.GetClients(db), handler.ValidSession)
	app.GET(util.BasePath+"/api/client/:id", handler.GetClient(db), handler.ValidSession)
	app.GET(util.BasePath+"/api/machine-ips", handler.MachineIPAddresses(), handler.ValidSession)
	app.GET(util.BasePath+"/api/suggest-client-ips", handler.SuggestIPAllocation(db), handler.ValidSession)
	app.POST(util.BasePath+"/api/apply-wg-config", handler.ApplyServerConfig(db, tmplDir), handler.ValidSession, handler.ContentTypeJson)
	app.GET(util.BasePath+"/wake_on_lan_hosts", handler.GetWakeOnLanHosts(db), handler.ValidSession)
	app.POST(util.BasePath+"/wake_on_lan_host", handler.SaveWakeOnLanHost(db), handler.ValidSession, handler.ContentTypeJson)
	app.DELETE(util.BasePath+"/wake_on_lan_host/:mac_address", handler.DeleteWakeOnHost(db), handler.ValidSession, handler.ContentTypeJson)
	app.PUT(util.BasePath+"/wake_on_lan_host/:mac_address", handler.WakeOnHost(db), handler.ValidSession, handler.ContentTypeJson)

	// strip the "assets/" prefix from the embedded directory so files can be called directly without the "assets/"
	// prefix
	assetsDir, _ := fs.Sub(fs.FS(embeddedAssets), "assets")
	assetHandler := http.FileServer(http.FS(assetsDir))
	// serves other static files
	app.GET(util.BasePath+"/static/*", echo.WrapHandler(http.StripPrefix(util.BasePath+"/static/", assetHandler)))

	app.Logger.Fatal(app.Start(util.BindAddress))
}

func initServerConfig(db store.IStore, tmplDir fs.FS) {
	settings, err := db.GetGlobalSettings()
	if err != nil {
		log.Fatalf("Cannot get global settings: ", err)
	}

	if _, err := os.Stat(settings.ConfigFilePath); err == nil {
		// file exists, don't overwrite it implicitly
		return
	}

	server, err := db.GetServer()
	if err != nil {
		log.Fatalf("Cannot get server config: ", err)
	}

	clients, err := db.GetClients(false)
	if err != nil {
		log.Fatalf("Cannot get client config: ", err)
	}

	users, err := db.GetUsers()
	if err != nil {
		log.Fatalf("Cannot get user config: ", err)
	}

	// write config file
	err = util.WriteWireGuardServerConfig(tmplDir, server, clients, users, settings)
	if err != nil {
		log.Fatalf("Cannot create server config: ", err)
	}
}
