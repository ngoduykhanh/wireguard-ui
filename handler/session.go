package handler

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

func ValidSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !isValidSession(c) {
			nextURL := c.Request().URL
			if nextURL != nil && c.Request().Method == http.MethodGet {
				return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf(util.BasePath+"/login?next=%s", c.Request().URL))
			} else {
				return c.Redirect(http.StatusTemporaryRedirect, util.BasePath+"/login")
			}
		}
		return next(c)
	}
}

func NeedsAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !isAdmin(c) {
			return c.Redirect(http.StatusTemporaryRedirect, util.BasePath+"/")
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

// isAdmin to get user type: admin or manager
func isAdmin(c echo.Context) bool {
	if util.DisableLogin {
		return true
	}

	sess, _ := session.Get("session", c)
	admin := fmt.Sprintf("%t", sess.Values["admin"])
	return admin == "true"
}

func setUser(c echo.Context, username string, admin bool) {
	sess, _ := session.Get("session", c)
	sess.Values["username"] = username
	sess.Values["admin"] = admin
	sess.Save(c.Request(), c.Response())
}

// clearSession to remove current session
func clearSession(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Values["username"] = ""
	sess.Values["admin"] = false
	sess.Values["session_token"] = ""
	sess.Save(c.Request(), c.Response())
}
