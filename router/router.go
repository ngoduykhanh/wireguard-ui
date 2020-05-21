package router

import (
	"errors"
	"io"
	"text/template"

	"github.com/GeertJohan/go.rice"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

// TemplateRegistry is a custom html/template renderer for Echo framework
type TemplateRegistry struct {
	templates map[string]*template.Template
}

// Render e.Renderer interface
func (t *TemplateRegistry) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, ok := t.templates[name]
	if !ok {
		err := errors.New("Template not found -> " + name)
		return err
	}
	// login page does not need the base layout
	if name == "login.html" {
		return tmpl.Execute(w, data)
	}
	return tmpl.ExecuteTemplate(w, "base.html", data)
}

// New function
func New() *echo.Echo {
	e := echo.New()
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))

	// create go rice box for embedded template
	templateBox, err := rice.FindBox("../templates")
	if err != nil {
		log.Fatal(err)
	}

	// read html template file to string
	tmplBaseString, err := templateBox.String("base.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplLoginString, err := templateBox.String("login.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplClientsString, err := templateBox.String("clients.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplServerString, err := templateBox.String("server.html")
	if err != nil {
		log.Fatal(err)
	}

	tmplGlobalSettingsString, err := templateBox.String("global_settings.html")
	if err != nil {
		log.Fatal(err)
	}

	// create template list
	templates := make(map[string]*template.Template)
	templates["login.html"] = template.Must(template.New("login").Parse(tmplLoginString))
	templates["clients.html"] = template.Must(template.New("clients").Parse(tmplBaseString + tmplClientsString))
	templates["server.html"] = template.Must(template.New("server").Parse(tmplBaseString + tmplServerString))
	templates["global_settings.html"] = template.Must(template.New("global_settings").Parse(tmplBaseString + tmplGlobalSettingsString))

	e.Logger.SetLevel(log.DEBUG)
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
	}))
	e.Validator = NewValidator()
	e.Renderer = &TemplateRegistry{
		templates: templates,
	}

	return e
}
