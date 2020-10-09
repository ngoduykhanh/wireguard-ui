package handler

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// validSession to redirect user to the login page if they are not authenticated or session expired.
func validSession(c echo.Context) {
	if !util.DisableLogin {
		sess, _ := session.Get("session", c)
		cookie, err := c.Cookie("session_token")
		if err != nil || sess.Values["session_token"] != cookie.Value {
			nextURL := c.Request().URL
			if nextURL != nil {
				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("/login?next=%s", c.Request().URL))
			} else {
				c.Redirect(http.StatusTemporaryRedirect, "/login")
			}
		}
	}
}

// currentUser to get username of logged in user
func currentUser(c echo.Context) string {
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
