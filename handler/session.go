package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// WebAuthn credential ID (RawURLEncoded) used for the current login, if login was via passkey.
const sessionPkLoginCredKey = "pk_login_cred"

// androidCompanionIdleMinSeconds is the minimum sliding idle window for requests that identify as the
// Flutter Android client (header X-WGUI-Client: android). Browser/HTML sessions keep using only
// global session_timeout_minutes from settings.
const androidCompanionIdleMinSeconds = 15 * 24 * 3600

const androidCompanionClientHeader = "X-WGUI-Client"
const androidCompanionClientValue = "android"

func isWireguardUiAndroidClient(c echo.Context) bool {
	return strings.EqualFold(strings.TrimSpace(c.Request().Header.Get(androidCompanionClientHeader)), androidCompanionClientValue)
}

func effectiveIdleSeconds(sess *sessions.Session, c echo.Context) int64 {
	maxAge := getMaxAge(sess)
	if maxAge <= 0 {
		maxAge = 86400
	}
	v := int64(maxAge)
	if isWireguardUiAndroidClient(c) && v < androidCompanionIdleMinSeconds {
		return androidCompanionIdleMinSeconds
	}
	return v
}

func effectiveIdleSecondsForCookie(sess *sessions.Session, c echo.Context) int {
	maxAge := getMaxAge(sess)
	if maxAge <= 0 {
		maxAge = 86400
	}
	if isWireguardUiAndroidClient(c) && maxAge < androidCompanionIdleMinSeconds {
		return androidCompanionIdleMinSeconds
	}
	return maxAge
}

func sessionPasskeyCredentialID(sess *sessions.Session) string {
	if sess == nil {
		return ""
	}
	s, _ := sess.Values[sessionPkLoginCredKey].(string)
	return strings.TrimSpace(s)
}

func ValidSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if util.DisableLogin {
			return next(c)
		}
		if !isValidSession(c) {
			nextURL := c.Request().URL
			if nextURL != nil && c.Request().Method == http.MethodGet {
				return c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf(util.BasePath+"/login?next=%s", c.Request().URL))
			} else {
				return c.Redirect(http.StatusTemporaryRedirect, util.BasePath+"/login")
			}
		}
		// Sliding idle timeout: treat this request as last activity for idle expiry.
		// Do not refresh cookies on /logout: it races with clearSession in the same response.
		if !strings.HasSuffix(c.Request().URL.Path, "/logout") {
			touchSessionIdle(c)
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
	idleWindow := effectiveIdleSeconds(sess, c)
	expiration := updatedAt + idleWindow
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
		Path:   cookiePath,
		MaxAge: maxAge,
	}
	util.ApplySessionSecureFlags(sess.Options)
	sess.Save(c.Request(), c.Response())

	cookie := new(http.Cookie)
	cookie.Name = "session_token"
	cookie.Path = cookiePath
	cookie.Value = oldCookie.Value
	cookie.MaxAge = maxAge
	util.ApplySessionHTTPFlags(cookie)
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
	case int32:
		return int(typedMaxAge)
	case int64:
		return int(typedMaxAge)
	case float64:
		return int(typedMaxAge)
	default:
		return 0
	}
}

// touchSessionIdle updates updated_at while session is alive so expires at (last_activity + max_age idle window).
func touchSessionIdle(c echo.Context) {
	sess, _ := session.Get("session", c)
	oldCookie, err := c.Cookie("session_token")
	if err != nil || sess.Values["session_token"] != oldCookie.Value {
		return
	}
	maxAge := effectiveIdleSecondsForCookie(sess, c)
	now := time.Now().UTC().Unix()
	sess.Values["updated_at"] = now

	cookiePath := util.GetCookiePath()
	sess.Options = &sessions.Options{
		Path:   cookiePath,
		MaxAge: maxAge,
	}
	util.ApplySessionSecureFlags(sess.Options)
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return
	}

	cookie := new(http.Cookie)
	cookie.Name = "session_token"
	cookie.Path = cookiePath
	cookie.Value = oldCookie.Value
	cookie.MaxAge = maxAge
	util.ApplySessionHTTPFlags(cookie)
	c.SetCookie(cookie)
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
	delete(sess.Values, sessionPkLoginCredKey)
	sess.Values["username"] = ""
	sess.Values["user_hash"] = 0
	sess.Values["admin"] = false
	sess.Values["session_token"] = ""
	sess.Values["max_age"] = -1
	cookiePath := util.GetCookiePath()
	sess.Options = &sessions.Options{
		Path:   cookiePath,
		MaxAge: -1,
	}
	util.ApplySessionSecureFlags(sess.Options)
	sess.Save(c.Request(), c.Response())

	cookie, err := c.Cookie("session_token")
	if err != nil {
		cookie = new(http.Cookie)
	}

	cookie.Name = "session_token"
	cookie.Path = cookiePath
	cookie.MaxAge = -1
	util.ApplySessionHTTPFlags(cookie)
	c.SetCookie(cookie)
}
