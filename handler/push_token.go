package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/pushnotify"
	"github.com/ngoduykhanh/wireguard-ui/store"
)

// RegisterPushToken stores an FCM device token for the current session user.
func RegisterPushToken(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var body struct {
			Token    string `json:"token"`
			Platform string `json:"platform"`
		}
		if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		token := strings.TrimSpace(body.Token)
		if token == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Missing token"})
		}
		un := currentUser(c)
		if err := pushnotify.RegisterOrUpdate(db.GetPath(), un, token, body.Platform); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "OK"})
	}
}

// UnregisterPushToken removes an FCM token (e.g. on logout).
func UnregisterPushToken(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		token := strings.TrimSpace(body.Token)
		if token == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Missing token"})
		}
		if err := pushnotify.Unregister(db.GetPath(), token); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "OK"})
	}
}
