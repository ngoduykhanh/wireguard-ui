package router

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"text/template"

	rice "github.com/GeertJohan/go.rice"
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
func New(tmplBox *rice.Box, extraData map[string]string, secret []byte) *echo.Echo {
	e := echo.New()
	e.Use(session.Middleware(sessions.NewCookieStore(secret)))

	// read html template file to string
	tmplBaseString, err := tmplBox.String("base.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplLoginString, err := tmplBox.String("login.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplProfileString, err := tmplBox.String("profile.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplClientsString, err := tmplBox.String("clients.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplServerString, err := tmplBox.String("server.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplGlobalSettingsString, err := tmplBox.String("global_settings.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplStatusString, err := tmplBox.String("status.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplWakeOnLanHostsString, err := tmplBox.String("wake_on_lan_hosts.html")
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
	templates["status.html"] = template.Must(template.New("status").Funcs(funcs).Parse(tmplBaseString + tmplStatusString))
	templates["wake_on_lan_hosts.html"] = template.Must(template.New("wake_on_lan_hosts").Funcs(funcs).Parse(tmplBaseString + tmplWakeOnLanHostsString))

	e.Logger.SetLevel(log.DEBUG)
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.HideBanner = true
	e.Validator = NewValidator()
	e.Renderer = &TemplateRegistry{
		templates: templates,
		extraData: extraData,
	}

	return e
}
