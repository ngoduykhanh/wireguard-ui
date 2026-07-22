package handler

import (
	"mime"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// ContentTypeJson checks that requests use application/json (including charset variants such as application/json; charset=UTF-8).
func ContentTypeJson(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		raw := strings.TrimSpace(c.Request().Header.Get("Content-Type"))
		if raw == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Only JSON allowed"})
		}
		mt, _, err := mime.ParseMediaType(raw)
		if err != nil || mt != "application/json" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Only JSON allowed"})
		}
		return next(c)
	}
}
