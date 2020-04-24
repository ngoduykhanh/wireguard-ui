package router

import (
	"errors"
	"io"
	"text/template"

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
	templates := make(map[string]*template.Template)
	templates["login.html"] = template.Must(template.ParseFiles("templates/login.html"))
	templates["clients.html"] = template.Must(template.ParseFiles("templates/clients.html", "templates/base.html"))
	templates["server.html"] = template.Must(template.ParseFiles("templates/server.html", "templates/base.html"))
	templates["global_settings.html"] = template.Must(template.ParseFiles("templates/global_settings.html", "templates/base.html"))

	e.Logger.SetLevel(log.DEBUG)
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
	}))
	e.Validator = NewValidator()
	e.Static("/static", "assets")
	e.Renderer = &TemplateRegistry{
		templates: templates,
	}

	return e
}
