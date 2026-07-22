package handler

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	htemplate "html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/rs/xid"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ngoduykhanh/wireguard-ui/emailer"
	"github.com/ngoduykhanh/wireguard-ui/locale"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/pushnotify"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/telegram"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

var usernameRegexp = regexp.MustCompile("^\\w[\\w\\-.]*$")
var downloadNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// ensureCanDemote returns an error if stripping admin would leave zero active administrators.
func ensureCanDemote(db store.IStore, adminUsername string) error {
	target, err := db.GetUserByName(adminUsername)
	if err != nil {
		return err
	}
	if !target.Admin {
		return nil
	}
	users, err := db.GetUsers()
	if err != nil {
		return err
	}
	others := 0
	for _, u := range users {
		if u.Username == adminUsername {
			continue
		}
		if u.Admin && !u.Disabled {
			others++
		}
	}
	if others < 1 {
		return fmt.Errorf("cannot remove last administrator")
	}
	return nil
}

// ensureLeavingActiveAdminWhenDisabling forbids disabling the last remaining active administrator.
func ensureLeavingActiveAdminWhenDisabling(db store.IStore, targetUsername, lang string) error {
	target, err := db.GetUserByName(targetUsername)
	if err != nil {
		return err
	}
	if !target.Admin || target.Disabled {
		return nil
	}
	users, err := db.GetUsers()
	if err != nil {
		return err
	}
	others := 0
	for _, u := range users {
		if u.Username == targetUsername {
			continue
		}
		if u.Admin && !u.Disabled {
			others++
		}
	}
	if others < 1 {
		return fmt.Errorf("%s", locale.T(lang, "api.need_another_active_admin"))
	}
	return nil
}

type passkeyListItem struct {
	CredentialID string `json:"credential_id"`
	Name         string `json:"name"`
	Fingerprint  string `json:"fingerprint"`
}

type userListItem struct {
	Username    string            `json:"username"`
	DisplayName string            `json:"display_name"`
	Email       string            `json:"email"`
	Admin       bool              `json:"admin"`
	Disabled    bool              `json:"disabled"`
	Passkeys    []passkeyListItem `json:"passkeys"`
}

func passkeyFingerprint(pub []byte) string {
	if len(pub) == 0 {
		return "—"
	}
	h := sha256.Sum256(pub)
	parts := make([]string, 0, 8)
	for i := 0; i < 8 && i < len(h); i++ {
		parts = append(parts, fmt.Sprintf("%02X", h[i]))
	}
	return strings.Join(parts, ":")
}

func buildPasskeyList(u model.User) []passkeyListItem {
	pks := make([]passkeyListItem, 0, len(u.Passkeys))
	for _, c := range u.Passkeys {
		idKey := base64.RawURLEncoding.EncodeToString(c.ID)
		nm := ""
		if u.PasskeyLabels != nil {
			nm = strings.TrimSpace(u.PasskeyLabels[idKey])
		}
		if nm == "" {
			nm = "Passkey"
		}
		pks = append(pks, passkeyListItem{
			CredentialID: idKey,
			Name:         nm,
			Fingerprint:  passkeyFingerprint(c.PublicKey),
		})
	}
	return pks
}

func buildUserList(users []model.User) []userListItem {
	out := make([]userListItem, 0, len(users))
	for _, u := range users {
		dn := strings.TrimSpace(u.DisplayName)
		if dn == "" {
			dn = u.Username
		}
		out = append(out, userListItem{
			Username:    u.Username,
			DisplayName: dn,
			Email:       strings.TrimSpace(u.Email),
			Admin:       u.Admin,
			Disabled:    u.Disabled,
			Passkeys:    buildPasskeyList(u),
		})
	}
	return out
}

// Health check handler
func Health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}
}

func Favicon() echo.HandlerFunc {
	return func(c echo.Context) error {
		if favicon, ok := os.LookupEnv(util.FaviconFilePathEnvVar); ok {
			return c.File(favicon)
		}
		return c.Redirect(http.StatusFound, util.BasePath+"/static/custom/img/favicon.ico")
	}
}

// LoginPage handler
func LoginPage(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, _ := db.GetGlobalSettings()
		uilang := locale.Normalize(gs.UILanguage)
		st := buildPublicLoginWGStatus(db, c, uilang)
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"passkeysEnabled":  gs.TOTPEnabled,
			"globalSettings":   gs,
			"UILang":           uilang,
			"WGMsgJSON":        locale.JSONForHTML(uilang),
			"loginStatusLine":  st.Message,
			"loginStatusState": st.State,
		})
	}
}

// publicLoginWGStatusResp is returned by GET /api/public/login-wg-status (no auth) and used for the login banner.
type publicLoginWGStatusResp struct {
	InterfaceUp bool   `json:"interface_up"`
	Iface       string `json:"iface"`
	ListenPort  int    `json:"listen_port"`
	Message     string `json:"message"`
	State       string `json:"state"` // active | inactive | unknown
}

func buildPublicLoginWGStatus(db store.IStore, c echo.Context, uiLang string) publicLoginWGStatusResp {
	gs, _ := db.GetGlobalSettings()
	lang := locale.Normalize(uiLang)
	srv, errSrv := db.GetServer()
	iface := util.WireGuardIfaceBasename(gs.ConfigFilePath)
	port := 51820
	if errSrv == nil && srv.Interface != nil && srv.Interface.ListenPort > 0 {
		port = srv.Interface.ListenPort
	}
	devicesVm, wgErrMsg, dbgErr := GatherWireGuardStatusDevices(db, c)
	if dbgErr != nil {
		return publicLoginWGStatusResp{
			Iface: iface, ListenPort: port,
			State:   "unknown",
			Message: fmt.Sprintf(locale.T(lang, "login.status.unavailable"), iface, port),
		}
	}
	if wgErrMsg != "" {
		return publicLoginWGStatusResp{
			Iface: iface, ListenPort: port,
			State:   "unknown",
			Message: fmt.Sprintf(locale.T(lang, "login.status.no_wg_read"), iface, port),
		}
	}
	up := false
	for _, d := range devicesVm {
		if d.Name == iface {
			up = true
			break
		}
	}
	if up {
		return publicLoginWGStatusResp{
			Iface: iface, ListenPort: port,
			InterfaceUp: true, State: "active",
			Message: fmt.Sprintf(locale.T(lang, "login.status.active"), iface, port),
		}
	}
	return publicLoginWGStatusResp{
		Iface: iface, ListenPort: port,
		State:   "inactive",
		Message: fmt.Sprintf(locale.T(lang, "login.status.inactive"), iface, port),
	}
}

// PublicLoginWireguardStatus exposes kernel WG presence for the login page (polling), without authentication.
func PublicLoginWireguardStatus(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, _ := db.GetGlobalSettings()
		uilang := locale.Normalize(gs.UILanguage)
		st := buildPublicLoginWGStatus(db, c, uilang)
		return c.JSON(http.StatusOK, st)
	}
}

// Login for signing in handler
func Login(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		username := data["username"].(string)
		password := data["password"].(string)
		rememberMe := data["rememberMe"].(bool)
		globalSettings, _ := db.GetGlobalSettings()
		lang := locale.Normalize(globalSettings.UILanguage)

		if !usernameRegexp.MatchString(username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}

		dbuser, err := db.GetUserByName(username)
		if err != nil {
			log.Infof("Cannot query user %s from DB", username)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Invalid credentials"})
		}

		userCorrect := subtle.ConstantTimeCompare([]byte(username), []byte(dbuser.Username)) == 1

		var passwordCorrect bool
		if dbuser.PasswordHash != "" {
			match, err := util.VerifyHash(dbuser.PasswordHash, password)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot verify password"})
			}
			passwordCorrect = match
		} else {
			passwordCorrect = subtle.ConstantTimeCompare([]byte(password), []byte(dbuser.Password)) == 1
		}

		if userCorrect && passwordCorrect {
			if dbuser.Disabled {
				return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, locale.T(lang, "api.account_disabled")})
			}
			if err := setLoginSession(c, dbuser, rememberMe, globalSettings.SessionTimeoutMinutes); err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, fmt.Sprintf("Cannot set session: %v", err)})
			}

			return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Logged in successfully"})
		}

		return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Invalid credentials"})
	}
}

// GetUsers returns a sanitized user list (no password material) for the admin UI.
func GetUsers(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		usersList, err := db.GetUsers()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot get user list: %v", err),
			})
		}
		return c.JSON(http.StatusOK, buildUserList(usersList))
	}
}

// GetUser handler returns a JSON object of single user
func GetUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		username := c.Param("username")

		if !usernameRegexp.MatchString(username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}

		if !isAdmin(c) && (username != currentUser(c)) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Manager cannot access other user data"})
		}

		userData, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		userData.Password = ""
		userData.PasswordHash = ""

		return c.JSON(http.StatusOK, userData)
	}
}

// GetCurrentUserPasskeys returns only the passkeys metadata for current logged-in user.
func GetCurrentUserPasskeys(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		un := currentUser(c)
		if !usernameRegexp.MatchString(un) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}
		u, err := db.GetUserByName(un)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		gs, _ := db.GetGlobalSettings()
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":            true,
			"username":          u.Username,
			"passkeys":          buildPasskeyList(u),
			"passkeys_enabled":  gs.TOTPEnabled,
		})
	}
}

// Logout to log a user out
func Logout() echo.HandlerFunc {
	return func(c echo.Context) error {
		clearSession(c)
		return c.Redirect(http.StatusTemporaryRedirect, util.BasePath+"/login")
	}
}

// LoadProfile to load user information
func LoadProfile(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gs.UILanguage)
		return renderShell(c, db, "profile.html", map[string]interface{}{
			"baseData":      model.BaseData{Active: "profile", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"page_subtitle": locale.T(lang, "profile.page_sub"),
		})
	}
}

// UsersSettings handler
func UsersSettings(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gs.UILanguage)
		return renderShell(c, db, "users_settings.html", map[string]interface{}{
			"baseData":      model.BaseData{Active: "users-settings", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"page_subtitle": locale.T(lang, "users.page_sub"),
		})
	}
}

// UpdateUser to update user information
func UpdateUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		gsLang, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gsLang.UILanguage)

		username, _ := data["username"].(string)
		password, _ := data["password"].(string)
		previousUsername, _ := data["previous_username"].(string)
		admin, _ := data["admin"].(bool)
		displayName, _ := data["display_name"].(string)
		email, _ := data["email"].(string)

		if !isAdmin(c) && (previousUsername != currentUser(c)) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Manager cannot access other user data"})
		}

		if !isAdmin(c) {
			admin = false
		}

		if !usernameRegexp.MatchString(previousUsername) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}

		user, err := db.GetUserByName(previousUsername)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, err.Error()})
		}

		user.DisplayName = strings.TrimSpace(displayName)
		user.Email = strings.TrimSpace(email)

		if username == "" || !usernameRegexp.MatchString(username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}
		user.Username = username

		if username != previousUsername {
			_, err := db.GetUserByName(username)
			if err == nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "This username is taken"})
			}
		}

		passwordChanged := strings.TrimSpace(password) != ""
		if passwordChanged {
			hash, err := util.HashPassword(password)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
			}
			user.PasswordHash = hash
		}

		if previousUsername != currentUser(c) {
			if !admin && user.Admin {
				if err := ensureCanDemote(db, previousUsername); err != nil {
					return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
				}
			}
			user.Admin = admin
		}

		if err := db.DeleteUser(previousUsername); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		if err := db.SaveUser(user); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		log.Infof("Updated user information successfully")

		if previousUsername == currentUser(c) {
			if passwordChanged {
				clearSession(c)
				return c.JSON(http.StatusOK, jsonHTTPReauthenticate{
					Status:         true,
					Message:        locale.T(lang, "api.password_updated_reauth"),
					Reauthenticate: true,
				})
			}
			setUser(c, user.Username, user.Admin, util.GetDBUserCRC32(user))
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated user information successfully"})
	}
}

// CreateUser to create new user
func CreateUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		var user model.User
		username, _ := data["username"].(string)
		password, _ := data["password"].(string)
		admin, _ := data["admin"].(bool)
		displayName, _ := data["display_name"].(string)
		email, _ := data["email"].(string)

		if username == "" || !usernameRegexp.MatchString(username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}
		user.Username = username
		user.DisplayName = strings.TrimSpace(displayName)
		user.Email = strings.TrimSpace(email)

		if strings.TrimSpace(password) == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide an initial password"})
		}

		{
			_, err := db.GetUserByName(username)
			if err == nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "This username is taken"})
			}
		}

		hash, err := util.HashPassword(password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		user.PasswordHash = hash

		user.Admin = admin

		if err := db.SaveUser(user); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		log.Infof("Created user successfully")

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Created user successfully"})
	}
}

// RemoveUser handler
func RemoveUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		err := json.NewDecoder(c.Request().Body).Decode(&data)

		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		username, _ := data["username"].(string)

		if !usernameRegexp.MatchString(username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}

		if username == currentUser(c) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "User cannot delete itself"})
		}
		tu, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		if tu.Admin {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Cannot delete administrator accounts"})
		}

		if err := db.DeleteUser(username); err != nil {
			log.Error("Cannot delete user: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot delete user from database"})
		}

		log.Infof("Removed user: %s", username)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "User removed"})
	}
}

// SetUserAdmin toggles administrator role (admin-only; cannot demote self or last admin).
func SetUserAdmin(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var body struct {
			Username string `json:"username"`
			Admin    bool   `json:"admin"`
		}
		if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		target := strings.TrimSpace(body.Username)
		if target == "" || !usernameRegexp.MatchString(target) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}
		u, err := db.GetUserByName(target)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		me := currentUser(c)
		if target == me && !body.Admin {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Cannot remove administrator role from yourself"})
		}
		if !body.Admin && u.Admin {
			if err := ensureCanDemote(db, target); err != nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
			}
		}
		u.Admin = body.Admin
		if err := db.SaveUser(u); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		if target == me {
			setUser(c, u.Username, u.Admin, util.GetDBUserCRC32(u))
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "User role updated"})
	}
}

// SetUserDisabled toggles suspended / disabled login for a user (admin-only).
func SetUserDisabled(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var body struct {
			Username string `json:"username"`
			Disabled bool   `json:"disabled"`
		}
		if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		target := strings.TrimSpace(body.Username)
		if target == "" || !usernameRegexp.MatchString(target) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}
		u, err := db.GetUserByName(target)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		me := currentUser(c)
		gs, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gs.UILanguage)
		if !body.Disabled {
			u.Disabled = false
			if err := db.SaveUser(u); err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
			}
			if target == me {
				setUser(c, u.Username, u.Admin, util.GetDBUserCRC32(u))
			}
			return c.JSON(http.StatusOK, jsonHTTPResponse{true, locale.T(lang, "api.user_enabled")})
		}
		if u.Disabled {
			return c.JSON(http.StatusOK, jsonHTTPResponse{true, locale.T(lang, "api.no_change")})
		}
		if err := ensureLeavingActiveAdminWhenDisabling(db, target, lang); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
		}
		u.Disabled = true
		if err := db.SaveUser(u); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		if target == me {
			clearSession(c)
			return c.JSON(http.StatusOK, jsonHTTPReauthenticate{
				Status:         true,
				Message:        locale.T(lang, "api.account_disabled_admin_reactive"),
				Reauthenticate: true,
			})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, locale.T(lang, "api.user_disabled")})
	}
}

// RevokeUserSessions bumps AuthEpoch to invalidate cookies for another user without disabling the account (admin-only).
func RevokeUserSessions(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var body struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		target := strings.TrimSpace(body.Username)
		if target == "" || !usernameRegexp.MatchString(target) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}
		u, err := db.GetUserByName(target)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		gs, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gs.UILanguage)
		if u.Disabled {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, locale.T(lang, "api.disabled_no_valid_sessions")})
		}
		u.AuthEpoch++
		if err := db.SaveUser(u); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		me := currentUser(c)
		if target == me {
			clearSession(c)
			return c.JSON(http.StatusOK, jsonHTTPReauthenticate{
				Status:         true,
				Message:        locale.T(lang, "api.session_revoked_reauth"),
				Reauthenticate: true,
			})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, locale.T(lang, "api.user_sessions_revoked")})
	}
}

// WireGuardClients handler
func WireGuardClients(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientDataList, err := db.GetClients(true)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot get client list: %v", err),
			})
		}

		globalSettings, _ := db.GetGlobalSettings()
		lang := locale.Normalize(globalSettings.UILanguage)

		return renderShell(c, db, "clients.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: "clients", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"clientDataList": clientDataList,
			"globalSettings": globalSettings,
			"page_subtitle":  locale.T(lang, "page.clients_sub"),
		})
	}
}

// Dashboard main summary page (mock shell).
func Dashboard(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gsUI, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gsUI.UILanguage)

		clientDataList, err := db.GetClients(true)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, fmt.Sprintf("Cannot get client list: %v", err)})
		}
		for i, clientData := range clientDataList {
			clientDataList[i] = util.FillClientSubnetRange(clientData)
		}

		devicesVm, wgErr, dberr := GatherWireGuardStatusDevices(db, c)
		if dberr != nil {
			return renderShellErr(c, db, http.StatusInternalServerError, "dashboard.html", map[string]interface{}{
				"baseData":      model.BaseData{Active: "dashboard", CurrentUser: currentUser(c), Admin: isAdmin(c)},
				"page_subtitle": locale.T(lang, "page.dashboard_sub"),
				"error":         dberr.Error(),
			})
		}

		onlineByPub := map[string]bool{}
		trafficByPub := map[string]PeerTrafficRow{}
		var recvTotal, xmitTotal int64
		if wgErr == "" {
			for _, d := range devicesVm {
				for _, p := range d.Peers {
					recvTotal += p.ReceivedBytes
					xmitTotal += p.TransmitBytes
					if p.Connected && p.PublicKey != "" {
						onlineByPub[p.PublicKey] = true
					}
					if p.PublicKey != "" {
						trafficByPub[p.PublicKey] = PeerTrafficRow{
							Rx: p.ReceivedBytes,
							Tx: p.TransmitBytes,
						}
					}
				}
			}
		}

		totalPeers := len(clientDataList)
		enabledPeers := 0
		onlineClients := 0
		for _, cd := range clientDataList {
			if cd.Client == nil {
				continue
			}
			if cd.Client.Enabled {
				enabledPeers++
			}
			if cd.Client.Enabled && onlineByPub[cd.Client.PublicKey] {
				onlineClients++
			}
		}
		offPeers := enabledPeers - onlineClients
		if offPeers < 0 {
			offPeers = 0
		}

		var recentSorted []model.ClientData
		for _, cd := range clientDataList {
			if cd.Client != nil {
				recentSorted = append(recentSorted, cd)
			}
		}
		sort.SliceStable(recentSorted, func(i, j int) bool {
			return recentSorted[i].Client.UpdatedAt.After(recentSorted[j].Client.UpdatedAt)
		})
		recentClients := recentSorted
		if len(recentClients) > 10 {
			recentClients = recentClients[:10]
		}

		server, _ := db.GetServer()
		globalSettings, _ := db.GetGlobalSettings()
		serverActive := wgErr == "" && len(devicesVm) > 0

		return renderShell(c, db, "dashboard.html", map[string]interface{}{
			"baseData":            model.BaseData{Active: "dashboard", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"page_subtitle":       locale.T(lang, "page.dashboard_sub"),
			"clientDataList":      clientDataList,
			"recentClients":       recentClients,
			"onlinePeerByPubKey":  onlineByPub,
			"peerTrafficByPubKey": trafficByPub,
			"devicesVm":           devicesVm,
			"wgStatusError":       wgErr,
			"totalPeers":          totalPeers,
			"enabledPeers":        enabledPeers,
			"onlineCount":         onlineClients,
			"offlineApprox":       offPeers,
			"bytesReceived":       recvTotal,
			"bytesTransmitted":    xmitTotal,
			"wgOK":                wgErr == "",
			"serverActive":        serverActive,
			"serverSummary":       server,
			"globalSettings":      globalSettings,
			"logTailEnvVarHint":   LogsTailEnvVarName,
		})
	}
}

// TrafficPage bandwidth-style view using live wg stats plus client names.
func TrafficPage(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gsUI, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gsUI.UILanguage)

		devicesVm, wgErr, dberr := GatherWireGuardStatusDevices(db, c)
		if dberr != nil {
			return renderShellErr(c, db, http.StatusInternalServerError, "traffic.html", map[string]interface{}{
				"baseData":      model.BaseData{Active: "traffic", CurrentUser: currentUser(c), Admin: isAdmin(c)},
				"page_subtitle": locale.T(lang, "page.traffic_sub"),
				"error":         dberr.Error(),
			})
		}

		var recvTotal, xmitTotal int64
		for _, d := range devicesVm {
			for _, p := range d.Peers {
				recvTotal += p.ReceivedBytes
				xmitTotal += p.TransmitBytes
			}
		}

		return renderShell(c, db, "traffic.html", map[string]interface{}{
			"baseData":         model.BaseData{Active: "traffic", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"page_subtitle":    locale.T(lang, "page.traffic_sub"),
			"devices":          devicesVm,
			"error":            wgErr,
			"bytesReceived":    recvTotal,
			"bytesTransmitted": xmitTotal,
		})
	}
}

// LogsPage shows last lines from WGUI_LOG_TAIL_PATH file if configured.
func LogsPage(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, _ := db.GetGlobalSettings()
		lang := locale.Normalize(globalSettings.UILanguage)
		iface := util.WireGuardIfaceBasename(globalSettings.ConfigFilePath)
		systemSections := ReadSystemLogSections(iface)
		lines := ReadLogTailLines(400)
		return renderShell(c, db, "logs.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: "logs", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"page_subtitle":  locale.T(lang, "page.logs_sub"),
			"ifaceName":      iface,
			"systemSections": systemSections,
			"logLines":       lines,
			"logTailUnset":   len(lines) == 0,
			"logEnvHint":     LogsTailEnvVarName,
		})
	}
}

// APISystemLogs returns fresh log sections for the Logs page when "Logs" live monitoring is enabled.
func APISystemLogs(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, _ := db.GetGlobalSettings()
		lang := locale.Normalize(globalSettings.UILanguage)
		if !globalSettings.RealtimeStatsEnabled {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, locale.T(lang, "api.logs_monitoring_disabled")})
		}
		iface := util.WireGuardIfaceBasename(globalSettings.ConfigFilePath)
		sections := ReadSystemLogSections(iface)
		fileLines := ReadLogTailLines(400)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"sections":       sections,
			"log_lines":      fileLines,
			"log_tail_unset": len(fileLines) == 0,
			"iface_name":     iface,
		})
	}
}

// APISetRealtimeStatsEnabled sets only [model.GlobalSetting.RealtimeStatsEnabled] (logs + live API gate).
// Same field as the web “live monitoring” toggle / nav Logs link. Admin-only; full read-modify-write to avoid
// partial POST /global-settings wiping other fields.
func APISetRealtimeStatsEnabled(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		prev, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		var body struct {
			Enabled bool `json:"realtime_stats_enabled"`
		}
		if err := c.Bind(&body); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid JSON"})
		}
		prev.RealtimeStatsEnabled = body.Enabled
		prev.UpdatedAt = time.Now().UTC()
		if err := db.SaveGlobalSettings(prev); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot save global settings"})
		}
		if err := util.UpdateHashes(db); err != nil {
			log.Errorf("UpdateHashes after realtime stats toggle: %v", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Saved but failed to update pending state"})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated global settings successfully"})
	}
}

// GetClients handler return a JSON list of Wireguard client data
func GetClients(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientDataList, err := db.GetClients(true)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot get client list: %v", err),
			})
		}

		for i, clientData := range clientDataList {
			clientDataList[i] = util.FillClientSubnetRange(clientData)
		}

		return c.JSON(http.StatusOK, clientDataList)
	}
}

// GetClient handler returns a JSON object of Wireguard client data
func GetClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientID := c.Param("id")

		if _, err := xid.FromString(clientID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid client ID"})
		}

		qrCodeSettings := model.QRCodeSettings{
			Enabled:    true,
			IncludeDNS: true,
			IncludeMTU: true,
		}

		clientData, err := db.GetClientByID(clientID, qrCodeSettings)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		return c.JSON(http.StatusOK, util.FillClientSubnetRange(clientData))
	}
}

// NewClient handler
func NewClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var client model.Client
		c.Bind(&client)

		// Validate Telegram userid if provided
		if client.TgUserid != "" {
			idNum, err := strconv.ParseInt(client.TgUserid, 10, 64)
			if err != nil || idNum == 0 {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Telegram userid must be a non-zero number"})
			}
		}

		// read server information
		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot fetch server from database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}

		// validate the input Allocation IPs
		allocatedIPs, err := util.GetAllocatedIPs("")
		check, err := util.ValidateIPAllocation(server.Interface.Addresses, allocatedIPs, client.AllocatedIPs)
		if !check {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, fmt.Sprintf("%s", err)})
		}

		// validate the input AllowedIPs
		if util.ValidateAllowedIPs(client.AllowedIPs) == false {
			log.Warnf("Invalid Allowed IPs input from user: %v", client.AllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Allowed IPs must be in CIDR format"})
		}

		// validate extra AllowedIPs
		if util.ValidateExtraAllowedIPs(client.ExtraAllowedIPs) == false {
			log.Warnf("Invalid Extra AllowedIPs input from user: %v", client.ExtraAllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Extra AllowedIPs must be in CIDR format"})
		}

		// gen ID
		guid := xid.New()
		client.ID = guid.String()

		// gen Wireguard key pair
		if client.PublicKey == "" {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				log.Error("Cannot generate wireguard key pair: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
			}
			client.PrivateKey = key.String()
			client.PublicKey = key.PublicKey().String()
		} else {
			_, err := wgtypes.ParseKey(client.PublicKey)
			if err != nil {
				log.Error("Cannot verify wireguard public key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot verify Wireguard public key"})
			}
			// check for duplicates
			clients, err := db.GetClients(false)
			if err != nil {
				log.Error("Cannot get clients for duplicate check")
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get clients for duplicate check"})
			}
			for _, other := range clients {
				if other.Client.PublicKey == client.PublicKey {
					log.Error("Duplicate Public Key")
					return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Duplicate Public Key"})
				}
			}
		}

		if client.PresharedKey == "" {
			presharedKey, err := wgtypes.GenerateKey()
			if err != nil {
				log.Error("Cannot generated preshared key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
					false, "Cannot generate Wireguard preshared key",
				})
			}
			client.PresharedKey = presharedKey.String()
		} else if client.PresharedKey == "-" {
			client.PresharedKey = ""
			log.Infof("skipped PresharedKey generation for user: %v", client.Name)
		} else {
			_, err := wgtypes.ParseKey(client.PresharedKey)
			if err != nil {
				log.Error("Cannot verify wireguard preshared key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot verify Wireguard preshared key"})
			}
		}
		client.CreatedAt = time.Now().UTC()
		client.UpdatedAt = client.CreatedAt

		// write client to the database
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, err.Error(),
			})
		}
		log.Infof("Created wireguard client: %v", client)
		omitFCM := strings.TrimSpace(c.Request().Header.Get(pushnotify.HeaderXWGUIFCMToken))
		pushnotify.PeerCreated(client.Name, omitFCM)

		return c.JSON(http.StatusOK, client)
	}
}

// EmailClient handler to send the configuration via email
func EmailClient(db store.IStore, mailer emailer.Emailer, emailSubject, emailContent string) echo.HandlerFunc {
	type clientIdEmailPayload struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}

	return func(c echo.Context) error {
		var payload clientIdEmailPayload
		c.Bind(&payload)
		// TODO validate email

		if _, err := xid.FromString(payload.ID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid client ID"})
		}

		qrCodeSettings := model.QRCodeSettings{
			Enabled:    true,
			IncludeDNS: true,
			IncludeMTU: true,
		}
		clientData, err := db.GetClientByID(payload.ID, qrCodeSettings)
		if err != nil {
			log.Errorf("Cannot generate client id %s config file for downloading: %v", payload.ID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		// build config
		server, _ := db.GetServer()
		globalSettings, _ := db.GetGlobalSettings()
		config := util.BuildClientConfig(*clientData.Client, server, globalSettings)

		cfgAtt := emailer.Attachment{Name: "wg0.conf", Data: []byte(config)}
		var attachments []emailer.Attachment
		if clientData.Client.PrivateKey != "" {
			qrdata, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(clientData.QRCode, "data:image/png;base64,"))
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "decoding: " + err.Error()})
			}
			qrAtt := emailer.Attachment{Name: "wg.png", Data: qrdata}
			attachments = []emailer.Attachment{cfgAtt, qrAtt}
		} else {
			attachments = []emailer.Attachment{cfgAtt}
		}
		err = mailer.Send(
			clientData.Client.Name,
			payload.Email,
			emailSubject,
			emailContent,
			attachments,
		)

		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Email sent successfully"})
	}
}

// SendTelegramClient handler to send the configuration via Telegram
func SendTelegramClient(db store.IStore) echo.HandlerFunc {
	type clientIdUseridPayload struct {
		ID     string `json:"id"`
		Userid string `json:"userid"`
	}
	return func(c echo.Context) error {
		var payload clientIdUseridPayload
		c.Bind(&payload)

		clientData, err := db.GetClientByID(payload.ID, model.QRCodeSettings{Enabled: false})
		if err != nil {
			log.Errorf("Cannot generate client id %s config file for downloading: %v", payload.ID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		// build config
		server, _ := db.GetServer()
		globalSettings, _ := db.GetGlobalSettings()
		config := util.BuildClientConfig(*clientData.Client, server, globalSettings)
		configData := []byte(config)
		var qrData []byte

		if clientData.Client.PrivateKey != "" {
			qrData, err = qrcode.Encode(config, qrcode.Medium, 512)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "qr gen: " + err.Error()})
			}
		}

		userid, err := strconv.ParseInt(clientData.Client.TgUserid, 10, 64)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "userid: " + err.Error()})
		}

		err = telegram.SendConfig(userid, clientData.Client.Name, configData, qrData, false)

		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Telegram message sent successfully"})
	}
}

// UpdateClient handler to update client information
func UpdateClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var _client model.Client
		c.Bind(&_client)

		if _, err := xid.FromString(_client.ID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid client ID"})
		}

		// validate client existence
		clientData, err := db.GetClientByID(_client.ID, model.QRCodeSettings{Enabled: false})
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		// Validate Telegram userid if provided
		if _client.TgUserid != "" {
			idNum, err := strconv.ParseInt(_client.TgUserid, 10, 64)
			if err != nil || idNum == 0 {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Telegram userid must be a non-zero number"})
			}
		}

		server, err := db.GetServer()
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{
				false, fmt.Sprintf("Cannot fetch server config: %s", err),
			})
		}
		client := *clientData.Client
		// validate the input Allocation IPs
		allocatedIPs, err := util.GetAllocatedIPs(client.ID)
		check, err := util.ValidateIPAllocation(server.Interface.Addresses, allocatedIPs, _client.AllocatedIPs)
		if !check {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, fmt.Sprintf("%s", err)})
		}

		// validate the input AllowedIPs
		if util.ValidateAllowedIPs(_client.AllowedIPs) == false {
			log.Warnf("Invalid Allowed IPs input from user: %v", _client.AllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Allowed IPs must be in CIDR format"})
		}

		if util.ValidateExtraAllowedIPs(_client.ExtraAllowedIPs) == false {
			log.Warnf("Invalid Allowed IPs input from user: %v", _client.ExtraAllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Extra Allowed IPs must be in CIDR format"})
		}

		// update Wireguard Client PublicKey
		if client.PublicKey != _client.PublicKey && _client.PublicKey != "" {
			_, err := wgtypes.ParseKey(_client.PublicKey)
			if err != nil {
				log.Error("Cannot verify provided Wireguard public key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot verify provided Wireguard public key"})
			}
			// check for duplicates
			clients, err := db.GetClients(false)
			if err != nil {
				log.Error("Cannot get client list for duplicate public key check")
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get client list for duplicate public key check"})
			}
			for _, other := range clients {
				if other.Client.PublicKey == _client.PublicKey {
					log.Error("Duplicate Public Key")
					return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Duplicate Public Key"})
				}
			}

			// When replacing any PublicKey, discard any locally stored Wireguard Client PrivateKey
			// Client PubKey no longer corresponds to locally stored PrivKey.
			// QR code (needs PrivateKey) for this client is no longer possible now.

			if client.PrivateKey != "" {
				client.PrivateKey = ""
			}
		}

		// update Wireguard Client PresharedKey
		if client.PresharedKey != _client.PresharedKey && _client.PresharedKey != "" {
			_, err := wgtypes.ParseKey(_client.PresharedKey)
			if err != nil {
				log.Error("Cannot verify provided Wireguard preshared key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot verify provided Wireguard preshared key"})
			}
		}

		// map new data
		client.Name = _client.Name
		client.Email = _client.Email
		client.TgUserid = _client.TgUserid
		client.Enabled = _client.Enabled
		client.UseServerDNS = _client.UseServerDNS
		client.AllocatedIPs = _client.AllocatedIPs
		client.AllowedIPs = _client.AllowedIPs
		client.ExtraAllowedIPs = _client.ExtraAllowedIPs
		client.Endpoint = _client.Endpoint
		client.PublicKey = _client.PublicKey
		client.PresharedKey = _client.PresharedKey
		client.UpdatedAt = time.Now().UTC()
		client.AdditionalNotes = strings.ReplaceAll(strings.Trim(_client.AdditionalNotes, "\r\n"), "\r\n", "\n")

		// write to the database
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		log.Infof("Updated client information successfully => %v", client)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated client successfully"})
	}
}

type setClientStatusPayload struct {
	ID     string `json:"id"`
	Status bool   `json:"status"`
}

// SetClientStatus handler to enable / disable a client
func SetClientStatus(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload setClientStatusPayload
		if err := json.NewDecoder(c.Request().Body).Decode(&payload); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}

		clientID := strings.TrimSpace(payload.ID)
		status := payload.Status

		if clientID == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid client ID"})
		}

		if _, err := xid.FromString(clientID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid client ID"})
		}

		clientData, err := db.GetClientByID(clientID, model.QRCodeSettings{Enabled: false})
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, err.Error()})
		}

		wasEnabled := clientData.Client.Enabled
		client := *clientData.Client

		client.Enabled = status
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		log.Infof("Changed client %s enabled status to %v", client.ID, status)
		if wasEnabled != status {
			omitFCM := strings.TrimSpace(c.Request().Header.Get(pushnotify.HeaderXWGUIFCMToken))
			pushnotify.PeerEnableChanged(client.Name, status, omitFCM)
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Changed client status successfully"})
	}
}

// DownloadClient handler
func DownloadClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientID := c.QueryParam("clientid")
		if clientID == "" {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Missing clientid parameter"})
		}

		if _, err := xid.FromString(clientID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid client ID"})
		}

		clientData, err := db.GetClientByID(clientID, model.QRCodeSettings{Enabled: false})
		if err != nil {
			log.Errorf("Cannot generate client id %s config file for downloading: %v", clientID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Client not found"})
		}

		// build config
		server, err := db.GetServer()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		globalSettings, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		config := util.BuildClientConfig(*clientData.Client, server, globalSettings)

		// create io reader from string
		reader := strings.NewReader(config)

		// set response header for downloading
		c.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%s.conf", clientData.Client.Name))
		return c.Stream(http.StatusOK, "text/conf", reader)
	}
}

// DownloadAllClientsZip exports all peer configs as a single zip.
func DownloadAllClientsZip(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientDataList, err := db.GetClients(false)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		if len(clientDataList) == 0 {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "No peers found"})
		}

		server, err := db.GetServer()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		globalSettings, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}

		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		usedNames := map[string]int{}

		for _, cd := range clientDataList {
			if cd.Client == nil {
				continue
			}
			cfg := util.BuildClientConfig(*cd.Client, server, globalSettings)
			base := strings.TrimSpace(cd.Client.Name)
			if base == "" {
				base = "peer-" + cd.Client.ID
			}
			base = downloadNameSanitizer.ReplaceAllString(base, "_")
			if base == "" {
				base = "peer-" + cd.Client.ID
			}
			base = strings.Trim(base, "._- ")
			if base == "" {
				base = "peer-" + cd.Client.ID
			}

			n := usedNames[base]
			usedNames[base] = n + 1
			name := base
			if n > 0 {
				name = fmt.Sprintf("%s_%d", base, n+1)
			}

			w, err := zw.Create(name + ".conf")
			if err != nil {
				_ = zw.Close()
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
			}
			if _, err := w.Write([]byte(cfg)); err != nil {
				_ = zw.Close()
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
			}
		}

		if err := zw.Close(); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}

		filename := fmt.Sprintf("wireguard-peers-%s.zip", time.Now().Format("20060102-150405"))
		c.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%s", filename))
		return c.Blob(http.StatusOK, "application/zip", buf.Bytes())
	}
}

// RemoveClient handler
func RemoveClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		client := new(model.Client)
		c.Bind(client)

		if _, err := xid.FromString(client.ID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid client ID"})
		}

		var removedName string
		if cd, err := db.GetClientByID(client.ID, model.QRCodeSettings{Enabled: false}); err == nil && cd.Client != nil {
			removedName = cd.Client.Name
		}

		// delete client from database

		if err := db.DeleteClient(client.ID); err != nil {
			log.Error("Cannot delete wireguard client: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot delete client from database"})
		}

		log.Infof("Removed wireguard client: %v", client)
		omitFCM := strings.TrimSpace(c.Request().Header.Get(pushnotify.HeaderXWGUIFCMToken))
		pushnotify.PeerRemoved(removedName, omitFCM)
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Client removed"})
	}
}

// WireGuardServer handler
func WireGuardServer(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot get server config: ", err)
		}

		globalSettings, gsErr := db.GetGlobalSettings()
		if gsErr != nil {
			log.Warn("Cannot get global settings for servidor page: ", gsErr)
		}

		listenUDP := 0
		if server.Interface != nil {
			listenUDP = server.Interface.ListenPort
		}

		ifaceName := util.WireGuardIfaceBasename(globalSettings.ConfigFilePath)
		devicesVm, wgErr, dbgErr := GatherWireGuardStatusDevices(db, c)
		if dbgErr != nil {
			log.Warn(" wg status unavailable: ", dbgErr)
			wgErr = dbgErr.Error()
			devicesVm = nil
		}
		banner := BuildServerBannerVM(ifaceName, devicesVm, wgErr, listenUDP, util.HostUptimeApprox())
		dnsCsv := strings.Join(globalSettings.DNSServers, ", ")
		lang := locale.Normalize(globalSettings.UILanguage)

		return renderShell(c, db, "server.html", map[string]interface{}{
			"baseData":          model.BaseData{Active: "wg-server", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"page_subtitle":     fmt.Sprintf(locale.T(lang, "page.server_sub_fmt"), ifaceName),
			"serverInterface":   server.Interface,
			"serverKeyPair":     server.KeyPair,
			"globalSettings":    globalSettings,
			"wgIfaceName":       ifaceName,
			"dnsCsv":            dnsCsv,
			"serverBanner":      banner,
			"allowWgQuick":      util.LookupEnvOrBool(util.AllowWgQuickCtlEnvVar, false),
			"needsWgConfApply": util.HashesChanged(db),
		})
	}
}

// WireGuardServerInterfaces handler
func WireGuardServerInterfaces(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var serverInterface model.ServerInterface
		c.Bind(&serverInterface)

		// validate the input addresses
		if util.ValidateServerAddresses(serverInterface.Addresses) == false {
			log.Warnf("Invalid server interface addresses input from user: %v", serverInterface.Addresses)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Interface IP address must be in CIDR format"})
		}

		serverInterface.UpdatedAt = time.Now().UTC()

		// write config to the database

		if err := db.SaveServerInterface(serverInterface); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Interface IP address must be in CIDR format"})
		}
		log.Infof("Updated wireguard server interfaces settings: %v", serverInterface)

		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Updated interface addresses successfully"})
	}
}

// WireGuardServerKeyPair handler to generate private and public keys
func WireGuardServerKeyPair(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		// gen Wireguard key pair
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Error("Cannot generate wireguard key pair: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
		}

		var serverKeyPair model.ServerKeypair
		serverKeyPair.PrivateKey = key.String()
		serverKeyPair.PublicKey = key.PublicKey().String()
		serverKeyPair.UpdatedAt = time.Now().UTC()

		if err := db.SaveServerKeyPair(serverKeyPair); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
		}
		log.Infof("Updated wireguard server interfaces settings: %v", serverKeyPair)

		return c.JSON(http.StatusOK, serverKeyPair)
	}
}

// GlobalSettings handler
func GlobalSettings(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, err := db.GetGlobalSettings()
		if err != nil {
			log.Error("Cannot get global settings: ", err)
		}

		dnsSrv := globalSettings.DNSServers
		if dnsSrv == nil {
			dnsSrv = []string{}
		}
		dnsJSON, errMarshal := json.Marshal(dnsSrv)
		if errMarshal != nil || len(dnsJSON) == 0 {
			dnsJSON = []byte("[]")
		}

		lang := locale.Normalize(globalSettings.UILanguage)
		return renderShell(c, db, "global_settings.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: "global-settings", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"globalSettings": globalSettings,
			"page_subtitle":  locale.T(lang, "settings.page_sub"),
			"dnsServersJS":   htemplate.JS(dnsJSON),
		})
	}
}

// Status handler
func Status(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gs.UILanguage)
		sub := locale.T(lang, "page.status_sub")

		devicesVm, wgErr, dbErr := GatherWireGuardStatusDevices(db, c)
		if dbErr != nil {
			return renderShellErr(c, db, http.StatusInternalServerError, "status.html", map[string]interface{}{
				"baseData":      model.BaseData{Active: "status", CurrentUser: currentUser(c), Admin: isAdmin(c)},
				"page_subtitle": sub,
				"error":         dbErr.Error(),
				"devices":       nil,
			})
		}
		if wgErr != "" {
			return renderShellErr(c, db, http.StatusInternalServerError, "status.html", map[string]interface{}{
				"baseData":      model.BaseData{Active: "status", CurrentUser: currentUser(c), Admin: isAdmin(c)},
				"page_subtitle": sub,
				"error":         wgErr,
				"devices":       nil,
			})
		}

		return renderShell(c, db, "status.html", map[string]interface{}{
			"baseData":      model.BaseData{Active: "status", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"page_subtitle": sub,
			"devices":       devicesVm,
			"error":         "",
		})
	}
}

// GlobalSettingSubmit handler to update the global settings
func GlobalSettingSubmit(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		prev, _ := db.GetGlobalSettings()
		var globalSettings model.GlobalSetting
		c.Bind(&globalSettings)
		disabledPasskeys := prev.TOTPEnabled && !globalSettings.TOTPEnabled

		// UI theme: dark by default; "auto" follows prefers-color-scheme in the browser.
		switch strings.ToLower(strings.TrimSpace(globalSettings.UITheme)) {
		case "light":
			globalSettings.UITheme = "light"
		case "auto":
			globalSettings.UITheme = "auto"
		default:
			globalSettings.UITheme = "dark"
		}

		// Global settings POST does not include Server-tab flags (ip_forward / DNS force / persist / auto-apply).
		// Keep previously stored DB values so they are not overwritten with false when saving other fields.
		globalSettings.IPForwardDesired = prev.IPForwardDesired
		globalSettings.GlobalDNSOverride = prev.GlobalDNSOverride
		globalSettings.PersistWgConfOnSave = prev.PersistWgConfOnSave
		globalSettings.AutoApplyWGOnSave = prev.AutoApplyWGOnSave

		if strings.TrimSpace(globalSettings.EndpointAddress) == "" {
			globalSettings.EndpointAddress = prev.EndpointAddress
		}
		if strings.TrimSpace(globalSettings.ConfigFilePath) == "" {
			globalSettings.ConfigFilePath = prev.ConfigFilePath
		}

		// validate the input dns server list
		if util.ValidateIPAddressList(globalSettings.DNSServers) == false {
			log.Warnf("Invalid DNS server list input from user: %v", globalSettings.DNSServers)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid DNS server address"})
		}

		if util.ValidateMTU(globalSettings.MTU) == false {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "MTU must be 1280..9000 or 0/empty to omit"})
		}

		// Session timeout — if the client omits the field or sends 0, keep the previous DB value
		st := globalSettings.SessionTimeoutMinutes
		if st <= 0 && prev.SessionTimeoutMinutes > 0 {
			globalSettings.SessionTimeoutMinutes = prev.SessionTimeoutMinutes
			st = globalSettings.SessionTimeoutMinutes
		}
		if st <= 0 {
			st = 30
		}
		if st < 5 {
			st = 5
		}
		if st > 1440 {
			st = 1440
		}
		globalSettings.SessionTimeoutMinutes = st

		globalSettings.UpdatedAt = time.Now().UTC()

		// write config to the database
		if err := db.SaveGlobalSettings(globalSettings); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot generate Wireguard key pair"})
		}

		// Only when this submit runs (save footer), not when toggling off Passkeys without saving yet.
		lang := locale.Normalize(globalSettings.UILanguage)
		if disabledPasskeys {
			if err := ClearStoredPasskeysForAllUsers(db); err != nil {
				log.Errorf("clear passkeys after disabling Passkeys: %v", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, locale.T(lang, "api.saved_passkeys_cleared_failed")})
			}
		}

		// Keep hashes.json in sync with global_settings.json so /test-hash does not
		// report spurious pending changes after applying settings from the UI.
		if err := util.UpdateHashes(db); err != nil {
			log.Errorf("Cannot update hashes after global settings save: %v", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Saved settings but failed to update pending state"})
		}

		log.Infof("Updated global settings: %v", globalSettings)

		// Do not logout here: the unified flow POSTs /global-settings then apply-wg-config to the kernel;
		// logging out would force re-login before re-applying. Instead refresh the current user's session digest.
		if disabledPasskeys && !util.DisableLogin {
			if me := currentUser(c); me != "" {
				if u, err := db.GetUserByName(me); err == nil {
					sess, _ := session.Get("session", c)
					delete(sess.Values, sessionPkLoginCredKey)
					setUser(c, u.Username, u.Admin, util.GetDBUserCRC32(u))
				}
			}
		}

		msg := "Updated global settings successfully"
		if disabledPasskeys {
			msg = locale.T(lang, "api.global_saved_passkeys_disabled_kernel")
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, msg})
	}
}

// MachineIPAddresses handler to get local interface ip addresses
func MachineIPAddresses() echo.HandlerFunc {
	return func(c echo.Context) error {
		// get private ip addresses
		interfaceList, err := util.GetInterfaceIPs()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot get machine ip addresses"})
		}

		// get public ip address
		// TODO: Remove the go-external-ip dependency
		publicInterface, err := util.GetPublicIP()
		if err != nil {
			log.Warn("Cannot get machine public ip address: ", err)
		} else {
			// prepend public ip to the list
			interfaceList = append([]model.Interface{publicInterface}, interfaceList...)
		}

		return c.JSON(http.StatusOK, interfaceList)
	}
}

// GetOrderedSubnetRanges handler to get the ordered list of subnet ranges
func GetOrderedSubnetRanges() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.JSON(http.StatusOK, util.SubnetRangesOrder)
	}
}

// SuggestIPAllocation handler to get the list of ip address for client
func SuggestIPAllocation(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot fetch server config from database: ", err)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
		}

		// return the list of suggestedIPs
		// we take the first available ip address from
		// each server's network addresses.
		suggestedIPs := make([]string, 0)
		allocatedIPs, err := util.GetAllocatedIPs("")
		if err != nil {
			log.Error("Cannot suggest ip allocation. Failed to get list of allocated ip addresses: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false, "Cannot suggest ip allocation: failed to get list of allocated ip addresses",
			})
		}

		sr := c.QueryParam("sr")
		searchCIDRList := make([]string, 0)
		found := false

		// Use subnet range or default to interface addresses
		if util.SubnetRanges[sr] != nil {
			for _, cidr := range util.SubnetRanges[sr] {
				searchCIDRList = append(searchCIDRList, cidr.String())
			}
		} else {
			searchCIDRList = append(searchCIDRList, server.Interface.Addresses...)
		}

		// Save only unique IPs
		ipSet := make(map[string]struct{})

		for _, cidr := range searchCIDRList {
			ip, err := util.GetAvailableIP(cidr, allocatedIPs, server.Interface.Addresses)
			if err != nil {
				log.Error("Failed to get available ip from a CIDR: ", err)
				continue
			}
			found = true
			if strings.Contains(ip, ":") {
				ipSet[fmt.Sprintf("%s/128", ip)] = struct{}{}
			} else {
				ipSet[fmt.Sprintf("%s/32", ip)] = struct{}{}
			}
		}

		if !found {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				false,
				"Cannot suggest ip allocation: failed to get available ip. Try a different subnet or deallocate some ips.",
			})
		}

		for ip := range ipSet {
			suggestedIPs = append(suggestedIPs, ip)
		}

		return c.JSON(http.StatusOK, suggestedIPs)
	}
}

func applyKernelAfterWritingWgConf(configFilePath string, wgQuickRestart bool) error {
	if wgQuickRestart {
		if err := util.RestartWgQuick(configFilePath); err != nil {
			log.Warnf("wg-quick restart after apply failed, trying wg syncconf (unconditional): %v", err)
			if synErr := util.WgForceSyncConfFromSavedFile(configFilePath); synErr != nil {
				return fmt.Errorf("WireGuard restart failed (%v) and syncconf fallback failed (%s): %w", err, configFilePath, synErr)
			}
			return nil
		}
		return nil
	}
	// With no wg-quick restart, optional syncconf must not fail when iface is absent (tunnel stopped on purpose).
	if util.ShouldApplySyncconfAfterWrite() && !util.WgTunnelIsRunning(configFilePath) {
		log.Infof("Skipping wg syncconf (tunnel down) after apply: %s", configFilePath)
		return nil
	}
	if synErr := util.WgSyncConfFromSavedFile(configFilePath); synErr != nil {
		return fmt.Errorf("config saved but kernel reload failed (%s): %w", configFilePath, synErr)
	}
	return nil
}

func applyWireGuardConfigToDisk(db store.IStore, tmplDir fs.FS, wgQuickRestart bool) error {
	server, err := db.GetServer()
	if err != nil {
		log.Error("Cannot get server config: ", err)
		return fmt.Errorf("cannot get server config: %w", err)
	}

	clients, err := db.GetClients(false)
	if err != nil {
		log.Error("Cannot get client config: ", err)
		return fmt.Errorf("cannot get client config: %w", err)
	}

	users, err := db.GetUsers()
	if err != nil {
		log.Error("Cannot get users config: ", err)
		return fmt.Errorf("cannot get users config: %w", err)
	}

	settings, err := db.GetGlobalSettings()
	if err != nil {
		log.Error("Cannot get global settings: ", err)
		return fmt.Errorf("cannot get global settings: %w", err)
	}

	canonical := strings.TrimSpace(settings.ConfigFilePath)
	outPath := canonical
	if wgQuickRestart {
		util.RemoveWgConfPending(canonical)
	} else if util.WgConfPendingWhenTunnelStopped() && runtime.GOOS == "linux" &&
		canonical != "" && filepath.IsAbs(canonical) && !util.WgTunnelIsRunning(canonical) {
		outPath = util.WgConfPendingPath(canonical)
		log.Infof("Applying wg config while tunnel stopped: writing pending file %s (canonical %s)", outPath, canonical)
	} else if canonical != "" {
		util.RemoveWgConfPending(canonical)
	}

	err = util.WriteWireGuardServerConfig(tmplDir, server, clients, users, settings, outPath)
	if err != nil {
		log.Error("Cannot apply server config: ", err)
		return err
	}

	err = util.UpdateHashes(db)
	if err != nil {
		log.Error("Cannot update hashes: ", err)
		return err
	}

	return applyKernelAfterWritingWgConf(canonical, wgQuickRestart)
}

// ApplyServerConfig writes wg.conf and applies it to the kernel. Optional JSON body:
//   - Empty body or omit restart_wireguard: restart only if util.WgTunnelIsRunning(ConfigFilePath) is true — avoids restarting a tunnel that was deliberately stopped via wg-quick down.
//   - {"restart_wireguard":false}: syncconf only (e.g. session/appearance-only changes plus config dump without bringing the iface down).
//   - {"restart_wireguard":true}: always run wg-quick restart (or systemd equivalent), even when the tunnel is currently down — use to bring WG up alongside applying the file.
func ApplyServerConfig(db store.IStore, tmplDir fs.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		gsSnap, gsErr := db.GetGlobalSettings()
		if gsErr != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot read global settings"})
		}
		restartWG := util.WgTunnelIsRunning(gsSnap.ConfigFilePath)

		body, errRead := io.ReadAll(c.Request().Body)
		if errRead != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Cannot read request body"})
		}
		if len(bytes.TrimSpace(body)) > 0 {
			var raw struct {
				Restart *bool `json:"restart_wireguard"`
			}
			if err := json.Unmarshal(body, &raw); err != nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid JSON body"})
			}
			if raw.Restart != nil {
				restartWG = *raw.Restart
			}
		}
		log.Infof("ApplyServerConfig: restart_wireguard=%v %s=%v", restartWG, util.AllowWgQuickCtlEnvVar, util.LookupEnvOrBool(util.AllowWgQuickCtlEnvVar, false))
		if err := applyWireGuardConfigToDisk(db, tmplDir, restartWG); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Applied server config successfully"})
	}
}

// wgServerPagePayload matches the Servidor tab combined save POST body (numbers as JSON ints, unlike model.ServerInterface form tags).
type wgServerPagePayload struct {
	Addresses           []string `json:"addresses"`
	ListenPort          int      `json:"listen_port"`
	PostUp              string   `json:"post_up"`
	PreDown             string   `json:"pre_down"`
	PostDown            string   `json:"post_down"`
	MTU                 int      `json:"mtu"`
	DNSServersRaw       string   `json:"dns_servers"`
	IPForwardDesired    bool     `json:"ip_forward_desired"`
	GlobalDNSOverride   bool     `json:"global_dns_override"`
	PersistWgConfOnSave bool     `json:"persist_wg_conf_on_save"`
	AutoApplyWGOnSave   bool     `json:"auto_apply_wg_on_save"`
}

// WireGuardServerSave stores interface + dns/mtu/options and optionally persists wg.conf to disk + sysctl ipv4 forwarding.
func WireGuardServerSave(db store.IStore, tmplDir fs.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		var payload wgServerPagePayload
		if err := c.Bind(&payload); err != nil {
			log.Warn(err)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, fmt.Sprintf("Invalid request format: %s", err.Error())})
		}

		if payload.ListenPort < 1 || payload.ListenPort > 65535 {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Listen port must be in range 1..65535"})
		}

		if util.ValidateServerAddresses(payload.Addresses) == false {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Interface IP address must be in CIDR format"})
		}

		if util.ValidateMTU(payload.MTU) == false {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "MTU must be 1280..9000 or 0/empty to omit"})
		}

		srvIf := model.ServerInterface{
			Addresses:  payload.Addresses,
			ListenPort: payload.ListenPort,
			PostUp:     payload.PostUp,
			PreDown:    payload.PreDown,
			PostDown:   payload.PostDown,
			UpdatedAt:  time.Now().UTC(),
		}
		if err := db.SaveServerInterface(srvIf); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot save server interface"})
		}

		gs, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot read global settings"})
		}

		gs.MTU = payload.MTU

		ds := make([]string, 0)
		for _, p := range strings.Split(payload.DNSServersRaw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				ds = append(ds, p)
			}
		}
		gs.DNSServers = ds
		if util.ValidateIPAddressList(gs.DNSServers) == false {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid DNS server address"})
		}

		gs.IPForwardDesired = payload.IPForwardDesired
		gs.GlobalDNSOverride = payload.GlobalDNSOverride
		gs.PersistWgConfOnSave = payload.PersistWgConfOnSave
		gs.AutoApplyWGOnSave = payload.AutoApplyWGOnSave
		gs.UpdatedAt = time.Now().UTC()

		if err := db.SaveGlobalSettings(gs); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot save settings"})
		}

		if err := util.ApplyIPv4ForwardSysctl(gs.IPForwardDesired); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, fmt.Sprintf("sysctl ipv4 forwarding: %s", err.Error())})
		}

		writeDisk := gs.PersistWgConfOnSave || gs.AutoApplyWGOnSave
		if writeDisk {
			if err := applyWireGuardConfigToDisk(db, tmplDir, false); err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
			}
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":               true,
			"message":              "Servidor actualizado",
			"needs_wg_conf_apply": util.HashesChanged(db),
		})
	}
}

// pushTunnelTransitionAfterWgQuick updates FCM tunnel notifications after wg-quick up/down from the API
// (same logic as GET /api/wireguard/tunnel-status, but triggered immediately when the tunnel changes).
func pushTunnelTransitionAfterWgQuick(db store.IStore) {
	gs, err := db.GetGlobalSettings()
	if err != nil {
		return
	}
	pushnotify.TunnelRunningTransition(util.WgTunnelIsRunning(gs.ConfigFilePath))
}

// WireGuardQuickStop runs wg-quick down when WGUI_ALLOW_WG_QUICK=true.
func WireGuardQuickStop(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot read global settings"})
		}
		if err := util.RunWgQuickDown(gs.ConfigFilePath); err != nil {
			log.Warn(err)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
		}
		pushTunnelTransitionAfterWgQuick(db)
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Interfaz detenida (wg-quick down)"})
	}
}

// WireGuardQuickStart runs wg-quick up when WGUI_ALLOW_WG_QUICK=true.
func WireGuardQuickStart(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot read global settings"})
		}
		if err := util.RunWgQuickUp(gs.ConfigFilePath); err != nil {
			log.Warn(err)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
		}
		pushTunnelTransitionAfterWgQuick(db)
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Interfaz iniciada (wg-quick up)"})
	}
}

// WireGuardTunnelStatus exposes util.WgTunnelIsRunning(gs.ConfigFilePath) for dashboards and tooling.
func WireGuardTunnelStatus(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Cannot read global settings"})
		}
		confPath := strings.TrimSpace(gs.ConfigFilePath)
		iface := util.WireGuardIfaceBasename(confPath)
		running := util.WgTunnelIsRunning(confPath)
		pushnotify.TunnelRunningTransition(running)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"tunnel_running": running,
			"iface_name":     iface,
		})
	}
}

// GetUINavHints returns navbar + shell prefs without a full page reload (badge, Logs, theme, HTML lang).
func GetUINavHints(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		badge := 0
		if db != nil && util.HashesChanged(db) {
			badge = 1
		}
		showLogs := false
		uiTheme := "dark"
		uiLang := "es"
		if gs, err := db.GetGlobalSettings(); err == nil {
			showLogs = gs.RealtimeStatsEnabled
			ut := strings.ToLower(strings.TrimSpace(gs.UITheme))
			switch ut {
			case "", "dark":
				uiTheme = "dark"
			case "light":
				uiTheme = "light"
			case "auto":
				uiTheme = "auto"
			default:
				uiTheme = "dark"
			}
			if ln := strings.ToLower(strings.TrimSpace(gs.UILanguage)); ln == "en" {
				uiLang = "en"
			}
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"dashboard_nav_badge": badge,
			"show_logs_nav":       showLogs,
			"ui_theme":            uiTheme,
			"ui_language":         uiLang,
		})
	}
}

// GetHashesChanges handler returns if database hashes have changed
func GetHashesChanges(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		if util.HashesChanged(db) {
			return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Hashes changed"})
		} else {
			return c.JSON(http.StatusOK, jsonHTTPResponse{false, "Hashes not changed"})
		}
	}
}

// AboutPage handler
func AboutPage(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		gs, _ := db.GetGlobalSettings()
		lang := locale.Normalize(gs.UILanguage)
		return renderShell(c, db, "about.html", map[string]interface{}{
			"baseData":      model.BaseData{Active: "about", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"page_subtitle": locale.T(lang, "page.about_sub"),
		})
	}
}
