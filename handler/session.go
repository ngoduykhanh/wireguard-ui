package handler

import (
	"fmt"
	"net/http"

	"github.com/alikhanich/wireguard-ui/util"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func ValidSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !isValidSession(c) {
			nextURL := c.Request().URL
			if nextURL != nil && c.Request().Method == http.MethodGet {
				return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf(util.BasePath + "/login?next=%s", c.Request().URL))
			} else {
				return c.Redirect(http.StatusTemporaryRedirect, util.BasePath + "/login")
			}
		}
		return next(c)
	}
}

func isValidSession(c echo.Context) bool {
	if util.DisableLogin {
		return true
	}
	sess, _ := session.Get("session", c)
	cookie, err := c.Cookie("session_token")
	apiKey, ok := sess.Values["api_key"].(string)
	if ok && apiKey == util.ApiKey {
		return true
	}
	//if ok && (apiKey != util.ApiKey || apiKey !="") {
	//	return false
	//}
	if err != nil || sess.Values["session_token"] != cookie.Value {
		return false
	}
	return true
}

// currentUser to get username of logged in user
func currentUser(c echo.Context) string {
	if util.DisableLogin {
		return ""
	}

	sess, _ := session.Get("session", c)
	username := fmt.Sprintf("%s", sess.Values["username"])
	return username
}

// clearSession to remove current session
func clearSession(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Values["username"] = ""
	sess.Values["session_token"] = ""
	sess.Save(c.Request(), c.Response())
}
