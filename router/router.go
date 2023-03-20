package router

import (
	"errors"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"text/template"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// TemplateRegistry is a custom html/template renderer for Echo framework
type TemplateRegistry struct {
	templates map[string]*template.Template
	extraData map[string]string
}

// Render e.Renderer interface
func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, ok := t.templates[name]
	if !ok {
		err := errors.New("Template not found -> " + name)
		return err
	}

	// inject more app data information. E.g. appVersion
	if reflect.TypeOf(data).Kind() == reflect.Map {
		for k, v := range t.extraData {
			data.(map[string]interface{})[k] = v
		}

		data.(map[string]interface{})["client_defaults"] = util.ClientDefaultsFromEnv()
	}

	// login page does not need the base layout
	if name == "login.html" {
		return tmpl.Execute(w, data)
	}

	return tmpl.ExecuteTemplate(w, "base.html", data)
}

// New function
func New(tmplDir fs.FS, extraData map[string]string, secret []byte) *echo.Echo {
	e := echo.New()
	e.Use(session.Middleware(sessions.NewCookieStore(secret)))

	// read html template file to string
	tmplBaseString, err := util.StringFromEmbedFile(tmplDir, "base.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplLoginString, err := util.StringFromEmbedFile(tmplDir, "login.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplProfileString, err := util.StringFromEmbedFile(tmplDir, "profile.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplClientsString, err := util.StringFromEmbedFile(tmplDir, "clients.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplServerString, err := util.StringFromEmbedFile(tmplDir, "server.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplGlobalSettingsString, err := util.StringFromEmbedFile(tmplDir, "global_settings.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplUsersSettingsString, err := util.StringFromEmbedFile(tmplDir, "users_settings.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplStatusString, err := util.StringFromEmbedFile(tmplDir, "status.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplWakeOnLanHostsString, err := util.StringFromEmbedFile(tmplDir, "wake_on_lan_hosts.html")
	if err != nil {
		log.Fatal(err)
	}

	aboutPageString, err := util.StringFromEmbedFile(tmplDir, "about.html")
	if err != nil {
		log.Fatal(err)
	}

	// create template list
	funcs := template.FuncMap{
		"StringsJoin": strings.Join,
	}
	templates := make(map[string]*template.Template)
	templates["login.html"] = template.Must(template.New("login").Funcs(funcs).Parse(tmplLoginString))
	templates["profile.html"] = template.Must(template.New("profile").Funcs(funcs).Parse(tmplBaseString + tmplProfileString))
	templates["clients.html"] = template.Must(template.New("clients").Funcs(funcs).Parse(tmplBaseString + tmplClientsString))
	templates["server.html"] = template.Must(template.New("server").Funcs(funcs).Parse(tmplBaseString + tmplServerString))
	templates["global_settings.html"] = template.Must(template.New("global_settings").Funcs(funcs).Parse(tmplBaseString + tmplGlobalSettingsString))
	templates["users_settings.html"] = template.Must(template.New("users_settings").Funcs(funcs).Parse(tmplBaseString + tmplUsersSettingsString))
	templates["status.html"] = template.Must(template.New("status").Funcs(funcs).Parse(tmplBaseString + tmplStatusString))
	templates["wake_on_lan_hosts.html"] = template.Must(template.New("wake_on_lan_hosts").Funcs(funcs).Parse(tmplBaseString + tmplWakeOnLanHostsString))
	templates["about.html"] = template.Must(template.New("about").Funcs(funcs).Parse(tmplBaseString + aboutPageString))

	lvl, err := util.ParseLogLevel(util.LookupEnvOrString(util.LogLevel, "INFO"))
	if err != nil {
		log.Fatal(err)
	}
	logConfig := middleware.DefaultLoggerConfig
	logConfig.Skipper = func(c echo.Context) bool {
		resp := c.Response()
		if resp.Status >= 500 && lvl > log.ERROR { // do not log if response is 5XX but log level is higher than ERROR
			return true
		} else if resp.Status >= 400 && lvl > log.WARN { // do not log if response is 4XX but log level is higher than WARN
			return true
		} else if lvl > log.DEBUG { // do not log if log level is higher than DEBUG
			return true
		}
		return false
	}

	e.Logger.SetLevel(lvl)
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.LoggerWithConfig(logConfig))
	e.HideBanner = true
	e.HidePort = lvl > log.INFO // hide the port output if the log level is higher than INFO
	e.Validator = NewValidator()
	e.Renderer = &TemplateRegistry{
		templates: templates,
		extraData: extraData,
	}

	return e
}
