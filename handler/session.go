package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
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

// RefreshSession must only be used after ValidSession middleware
// RefreshSession checks if the session is eligible for the refresh, but doesn't check if it's fully valid
func RefreshSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		doRefreshSession(c)
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

	// Check time bounds
	createdAt := getCreatedAt(sess)
	updatedAt := getUpdatedAt(sess)
	maxAge := getMaxAge(sess)
	// Temporary session is considered valid within 24h if browser is not closed before
	// This value is not saved and is used as virtual expiration
	if maxAge == 0 {
		maxAge = 86400
	}
	expiration := updatedAt + int64(maxAge)
	now := time.Now().UTC().Unix()
	if updatedAt > now || expiration < now || createdAt+util.SessionMaxDuration < now {
		return false
	}

	// Check if user still exists and unchanged
	username := fmt.Sprintf("%s", sess.Values["username"])
	userHash := getUserHash(sess)
	if uHash, ok := util.DBUsersToCRC32[username]; !ok || userHash != uHash {
		return false
	}

	return true
}

// Refreshes a "remember me" session when the user visits web pages (not API)
// Session must be valid before calling this function
// Refresh is performed at most once per 24h
func doRefreshSession(c echo.Context) {
	if util.DisableLogin {
		return
	}

	sess, _ := session.Get("session", c)
	maxAge := getMaxAge(sess)
	if maxAge <= 0 {
		return
	}

	oldCookie, err := c.Cookie("session_token")
	if err != nil || sess.Values["session_token"] != oldCookie.Value {
		return
	}

	// Refresh no sooner than 24h
	createdAt := getCreatedAt(sess)
	updatedAt := getUpdatedAt(sess)
	expiration := updatedAt + int64(getMaxAge(sess))
	now := time.Now().UTC().Unix()
	if updatedAt > now || expiration < now || now-updatedAt < 86_400 || createdAt+util.SessionMaxDuration < now {
		return
	}

	cookiePath := util.GetCookiePath()

	sess.Values["updated_at"] = now
	sess.Options = &sessions.Options{
		Path:     cookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	sess.Save(c.Request(), c.Response())

	cookie := new(http.Cookie)
	cookie.Name = "session_token"
	cookie.Path = cookiePath
	cookie.Value = oldCookie.Value
	cookie.MaxAge = maxAge
	cookie.HttpOnly = true
	cookie.SameSite = http.SameSiteLaxMode
	c.SetCookie(cookie)
}

// Get time in seconds this session is valid without updating
func getMaxAge(sess *sessions.Session) int {
	if util.DisableLogin {
		return 0
	}

	maxAge := sess.Values["max_age"]

	switch typedMaxAge := maxAge.(type) {
	case int:
		return typedMaxAge
	default:
		return 0
	}
}

// Get a timestamp in seconds of the time the session was created
func getCreatedAt(sess *sessions.Session) int64 {
	if util.DisableLogin {
		return 0
	}

	createdAt := sess.Values["created_at"]

	switch typedCreatedAt := createdAt.(type) {
	case int64:
		return typedCreatedAt
	default:
		return 0
	}
}

// Get a timestamp in seconds of the last session update
func getUpdatedAt(sess *sessions.Session) int64 {
	if util.DisableLogin {
		return 0
	}

	lastUpdate := sess.Values["updated_at"]

	switch typedLastUpdate := lastUpdate.(type) {
	case int64:
		return typedLastUpdate
	default:
		return 0
	}
}

// Get CRC32 of a user at the moment of log in
// Any changes to user will result in logout of other (not updated) sessions
func getUserHash(sess *sessions.Session) uint32 {
	if util.DisableLogin {
		return 0
	}

	userHash := sess.Values["user_hash"]

	switch typedUserHash := userHash.(type) {
	case uint32:
		return typedUserHash
	default:
		return 0
	}
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

func setUser(c echo.Context, username string, admin bool, userCRC32 uint32) {
	sess, _ := session.Get("session", c)
	sess.Values["username"] = username
	sess.Values["user_hash"] = userCRC32
	sess.Values["admin"] = admin
	sess.Save(c.Request(), c.Response())
}

// clearSession to remove current session
func clearSession(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Values["username"] = ""
	sess.Values["user_hash"] = 0
	sess.Values["admin"] = false
	sess.Values["session_token"] = ""
	sess.Values["max_age"] = -1
	sess.Options.MaxAge = -1
	sess.Save(c.Request(), c.Response())

	cookiePath := util.GetCookiePath()

	cookie, err := c.Cookie("session_token")
	if err != nil {
		cookie = new(http.Cookie)
	}

	cookie.Name = "session_token"
	cookie.Path = cookiePath
	cookie.MaxAge = -1
	cookie.HttpOnly = true
	cookie.SameSite = http.SameSiteLaxMode
	c.SetCookie(cookie)
}
