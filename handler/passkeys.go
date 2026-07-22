package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/rs/xid"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/ngoduykhanh/wireguard-ui/locale"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

type webAuthnUser struct {
	u model.User
}

var (
	passkeyRegMu       sync.Mutex
	passkeyRegSessions = map[string]webauthn.SessionData{}
	passkeyLoginMu       sync.Mutex
	passkeyLoginSessions = map[string]webauthn.SessionData{}
)

// ClearStoredPasskeysForAllUsers removes WebAuthn credentials from every user (e.g. after disabling Passkeys in settings).
func ClearStoredPasskeysForAllUsers(db store.IStore) error {
	if db == nil {
		return nil
	}
	users, err := db.GetUsers()
	if err != nil {
		return err
	}
	for _, u := range users {
		if len(u.Passkeys) == 0 {
			continue
		}
		u.Passkeys = nil
		if err := db.SaveUser(u); err != nil {
			return fmt.Errorf("%s: %w", u.Username, err)
		}
	}
	return nil
}

func (w webAuthnUser) WebAuthnID() []byte {
	return []byte(w.u.Username)
}
func (w webAuthnUser) WebAuthnName() string {
	return w.u.Username
}
func (w webAuthnUser) WebAuthnDisplayName() string {
	if s := strings.TrimSpace(w.u.DisplayName); s != "" {
		return s
	}
	return w.u.Username
}
func (w webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return w.u.Passkeys
}
func (w webAuthnUser) WebAuthnIcon() string { return "" }

// androidApkOriginsFromPasskeySHA256Env builds WebAuthn origins for Credential Manager using the Android app
// signing key (same hex SHA-256 as WGUI_ANDROID_PASSKEY_SHA256 / assetlinks). ClientDataJSON.origin for native
// login is typically "android:apk-key-hash:"+base64url(SHA256(cert)) — see FullyQualifiedOrigin in go-webauthn.
func androidApkOriginsFromPasskeySHA256Env() []string {
	csv := util.AndroidPasskeySHA256FingerprintsCSV()
	if csv == "" {
		return nil
	}
	var out []string
	for _, frag := range strings.Split(csv, ",") {
		fp, err := normalizeAndroidCertFingerprint(strings.TrimSpace(frag))
		if err != nil {
			continue
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(fp, ":", ""))
		if err != nil || len(raw) != sha256digestLen {
			continue
		}
		out = append(out, androidApkOriginPrefix+base64.RawURLEncoding.EncodeToString(raw))
	}
	return out
}

const (
	sha256digestLen       = 32
	androidApkOriginPrefix = "android:apk-key-hash:"
)

func rpOriginsContainsExact(origins []string, needle string) bool {
	for _, o := range origins {
		if o == needle {
			return true
		}
	}
	return false
}

func webauthnForRequest(c echo.Context) (*webauthn.WebAuthn, error) {
	reqHost := c.Request().Header.Get("X-Forwarded-Host")
	if reqHost == "" {
		reqHost = c.Request().Host
	}
	if strings.Contains(reqHost, ",") {
		reqHost = strings.TrimSpace(strings.Split(reqHost, ",")[0])
	}
	proto := c.Request().Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if c.Request().TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	proto = strings.TrimSpace(strings.ToLower(proto))

	defaultOrigin := webauthnBuildOrigin(proto, reqHost)
	rpHost := webauthnHostOnlyFromRequest(reqHost)
	if rpHost == "" {
		rpHost = "localhost"
	}

	rpDisplayName := util.LookupEnvOrString(util.WebAuthnRPDisplayNameEnvVar, "WireGuard UI")
	envRPID := util.LookupEnvOrString(util.WebAuthnRPIDEnvVar, "")

	rpOrigins := trimOriginList(util.LookupEnvOrStrings(util.WebAuthnRPOriginsEnvVar, []string{defaultOrigin}))
	if len(rpOrigins) == 0 {
		rpOrigins = []string{defaultOrigin}
	}

	mobileRpHostForced := false
	if hint := strings.TrimSpace(c.Request().Header.Get(util.WebAuthnPublicOriginHeader)); hint != "" {
		norm, err := normalizeWebAuthnOrigin(hint)
		if err == nil && mobilePasskeyOriginTrusted(norm, rpOrigins, envRPID, defaultOrigin) {
			mobileRpHostForced = true
			if u, errP := url.Parse(norm); errP == nil && u.Hostname() != "" {
				rpHost = u.Hostname()
			}
			if !originListContainsNormalized(rpOrigins, norm) {
				rpOrigins = append([]string{norm}, rpOrigins...)
			}
		}
	}

	// Credential Manager verifies https://<rpId>/.well-known/assetlinks.json. That host must match
	// rp.id in WebAuthn options. If clients send X-WGUI-WebAuthn-Public-Origin (public HTTPS host)
	// but WGUI_WEBAUTHN_RP_ID was set for an internal LAN hostname, rp.id would mismatch and Android
	// raises "RP ID cannot be validated" before the assertion reaches our server.
	rpID := strings.TrimSpace(envRPID)
	if rpID == "" {
		rpID = rpHost
	} else if mobileRpHostForced && rpHost != "" &&
		!strings.EqualFold(hostOnlyRPID(rpID), rpHost) {
		log.Warnf("[passkeys] WGUI_WEBAUTHN_RP_ID %q disagrees with %s rp host %q; using hinted host so Android Credential Manager can validate RP ID",
			rpID, util.WebAuthnPublicOriginHeader, rpHost)
		rpID = rpHost
	}

	androidConfigured := strings.TrimSpace(util.AndroidPasskeySHA256FingerprintsCSV()) != ""
	for _, ao := range androidApkOriginsFromPasskeySHA256Env() {
		if !rpOriginsContainsExact(rpOrigins, ao) {
			rpOrigins = append(rpOrigins, ao)
		}
	}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
		// Hybrid / native Credential Manager assertions may set CollectedClientData.crossOrigin=true.
		RPAllowCrossOrigin: androidConfigured,
	})
}

func webauthnBuildOrigin(proto, hostPort string) string {
	u := &url.URL{Scheme: proto, Host: strings.TrimSpace(hostPort)}
	return strings.TrimSuffix(u.String(), "/")
}

func webauthnHostOnlyFromRequest(hostPort string) string {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		if i := strings.LastIndex(hostPort, ":"); i > 0 && !strings.HasPrefix(hostPort, "[") {
			return strings.ToLower(hostPort[:i])
		}
		return strings.ToLower(hostPort)
	}
	return strings.ToLower(h)
}

func trimOriginList(origins []string) []string {
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		s := strings.TrimSpace(o)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func normalizeWebAuthnOrigin(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty origin")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid origin")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("invalid origin host")
	}
	port := u.Port()
	if scheme != "https" && !(scheme == "http" && (host == "localhost" || strings.HasPrefix(host, "127."))) {
		return "", fmt.Errorf("origin must use https (http allowed only for localhost)")
	}
	if port != "" && !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		return fmt.Sprintf("%s://%s:%s", scheme, host, port), nil
	}
	return scheme + "://" + host, nil
}

func originListContainsNormalized(origins []string, norm string) bool {
	for _, o := range origins {
		no, err := normalizeWebAuthnOrigin(strings.TrimSpace(o))
		if err == nil && strings.EqualFold(no, norm) {
			return true
		}
	}
	return false
}

func hostOnlyRPID(rp string) string {
	rp = strings.TrimSpace(strings.ToLower(rp))
	if rp == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(rp); err == nil {
		return h
	}
	return rp
}

func mobilePasskeyOriginTrusted(norm string, rpOrigins []string, envRPID string, defaultOrigin string) bool {
	if originListContainsNormalized(rpOrigins, norm) {
		return true
	}
	if envRPID != "" {
		if u, err := url.Parse(norm); err == nil {
			if strings.EqualFold(u.Hostname(), hostOnlyRPID(envRPID)) {
				return true
			}
		}
	}
	if do, err := normalizeWebAuthnOrigin(defaultOrigin); err == nil && strings.EqualFold(do, norm) {
		return true
	}
	return strings.EqualFold(strings.TrimRight(defaultOrigin, "/"), strings.TrimRight(norm, "/"))
}

func setLoginSession(c echo.Context, dbuser model.User, rememberMe bool, sessionTimeoutMinutes int) error {
	ageMax := 0
	if sessionTimeoutMinutes > 0 {
		ageMax = sessionTimeoutMinutes * 60
	} else if rememberMe {
		// Only extend cookie max-age when global settings do not enforce a finite session idle timeout.
		rememberAge := 86400 * 7
		if ageMax < rememberAge {
			ageMax = rememberAge
		}
	}
	if ageMax <= 0 {
		ageMax = 86400
	}
	if isWireguardUiAndroidClient(c) && ageMax < androidCompanionIdleMinSeconds {
		ageMax = androidCompanionIdleMinSeconds
	}

	cookiePath := util.GetCookiePath()
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:   cookiePath,
		MaxAge: ageMax,
	}
	util.ApplySessionSecureFlags(sess.Options)

	tokenUID := xid.New().String()
	now := time.Now().UTC().Unix()
	userCRC := util.GetDBUserCRC32(dbuser)
	util.DBUsersToCRC32[dbuser.Username] = userCRC

	delete(sess.Values, sessionPkLoginCredKey)
	sess.Values["username"] = dbuser.Username
	sess.Values["user_hash"] = userCRC
	sess.Values["admin"] = dbuser.Admin
	sess.Values["session_token"] = tokenUID
	sess.Values["max_age"] = ageMax
	sess.Values["created_at"] = now
	sess.Values["updated_at"] = now
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return err
	}

	cookie := new(http.Cookie)
	cookie.Name = "session_token"
	cookie.Path = cookiePath
	cookie.Value = tokenUID
	cookie.MaxAge = ageMax
	util.ApplySessionHTTPFlags(cookie)
	c.SetCookie(cookie)
	return nil
}

func persistSessionPasskeyLoginCredential(c echo.Context, cred *webauthn.Credential) {
	if cred == nil || len(cred.ID) == 0 {
		return
	}
	sess, _ := session.Get("session", c)
	sess.Values[sessionPkLoginCredKey] = base64.RawURLEncoding.EncodeToString(cred.ID)
	_ = sess.Save(c.Request(), c.Response())
}

func PasskeyBeginRegister(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, _ := db.GetGlobalSettings()
		if !globalSettings.TOTPEnabled {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Passkeys are disabled in settings"})
		}
		username := c.Param("username")
		if username == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Missing username"})
		}
		if !isAdmin(c) && username != currentUser(c) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Not allowed"})
		}
		u, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		wa, err := webauthnForRequest(c)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		// Prefer resident (discoverable) credentials so login without username works on supported authenticators.
		opts, sessionData, err := wa.BeginRegistration(webAuthnUser{u}, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		sess, _ := session.Get("session", c)
		token := xid.New().String()
		passkeyRegMu.Lock()
		passkeyRegSessions[token] = *sessionData
		passkeyRegMu.Unlock()
		sess.Values["passkey_reg_"+username] = token
		_ = sess.Save(c.Request(), c.Response())
		return c.JSON(http.StatusOK, opts)
	}
}

func PasskeyFinishRegister(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, _ := db.GetGlobalSettings()
		if !globalSettings.TOTPEnabled {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Passkeys are disabled in settings"})
		}
		username := c.Param("username")
		if username == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Missing username"})
		}
		if !isAdmin(c) && username != currentUser(c) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Not allowed"})
		}
		u, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		bodyBytes, errRead := io.ReadAll(c.Request().Body)
		if errRead != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Cannot read request body"})
		}
		var raw map[string]interface{}
		credentialName := ""
		if json.Unmarshal(bodyBytes, &raw) == nil && raw != nil {
			if v, ok := raw["credential_name"].(string); ok {
				credentialName = strings.TrimSpace(v)
			}
			delete(raw, "credential_name")
			if clean, errM := json.Marshal(raw); errM == nil {
				bodyBytes = clean
			}
		}
		c.Request().Body = io.NopCloser(bytes.NewReader(bodyBytes))

		wa, err := webauthnForRequest(c)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		sess, _ := session.Get("session", c)
		token, _ := sess.Values["passkey_reg_"+username].(string)
		if token == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Registration session not found"})
		}
		passkeyRegMu.Lock()
		sessionData, ok := passkeyRegSessions[token]
		passkeyRegMu.Unlock()
		if !ok {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Registration session expired"})
		}
		cred, err := wa.FinishRegistration(webAuthnUser{u}, sessionData, c.Request())
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
		}
		already := false
		for _, ex := range u.Passkeys {
			if len(ex.ID) > 0 && bytes.Equal(ex.ID, cred.ID) {
				already = true
				break
			}
		}
		if !already {
			u.Passkeys = append(u.Passkeys, *cred)
			idKey := base64.RawURLEncoding.EncodeToString(cred.ID)
			if credentialName != "" {
				if u.PasskeyLabels == nil {
					u.PasskeyLabels = map[string]string{}
				}
				u.PasskeyLabels[idKey] = credentialName
			}
			if err := db.SaveUser(u); err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
			}
			if username == currentUser(c) {
				// Keep session hash in the same session instance; a second sess.Save() happens below.
				sess.Values["username"] = u.Username
				sess.Values["admin"] = u.Admin
				sess.Values["user_hash"] = util.GetDBUserCRC32(u)
			}
		}
		delete(sess.Values, "passkey_reg_"+username)
		passkeyRegMu.Lock()
		delete(passkeyRegSessions, token)
		passkeyRegMu.Unlock()
		_ = sess.Save(c.Request(), c.Response())
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Passkey registered"})
	}
}

// PasskeyRemove deletes one stored credential by id (base64url).
func PasskeyRemove(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, _ := db.GetGlobalSettings()
		if !globalSettings.TOTPEnabled {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Passkeys are disabled in settings"})
		}
		lang := locale.Normalize(globalSettings.UILanguage)
		var body struct {
			Username     string `json:"username"`
			CredentialID string `json:"credential_id"`
		}
		if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		un := strings.TrimSpace(body.Username)
		if un == "" || !usernameRegexp.MatchString(un) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid username"})
		}
		if !isAdmin(c) && un != currentUser(c) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Not allowed"})
		}
		wantID, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(body.CredentialID))
		if err != nil || len(wantID) == 0 {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid credential id"})
		}
		idKey := base64.RawURLEncoding.EncodeToString(wantID)
		u, err := db.GetUserByName(un)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		kept := u.Passkeys[:0]
		for _, pc := range u.Passkeys {
			if len(pc.ID) > 0 && bytes.Equal(pc.ID, wantID) {
				continue
			}
			kept = append(kept, pc)
		}
		if len(kept) == len(u.Passkeys) {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Credential not found"})
		}
		u.Passkeys = kept
		if u.PasskeyLabels != nil {
			delete(u.PasskeyLabels, idKey)
		}
		// Any passkey removal revokes existing sessions for that account.
		u.AuthEpoch++
		if err := db.SaveUser(u); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		if un == currentUser(c) {
			clearSession(c)
			return c.JSON(http.StatusOK, jsonHTTPReauthenticate{
				Status:         true,
				Message:        locale.T(lang, "api.passkey_removed_reauth"),
				Reauthenticate: true,
			})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{Status: true, Message: locale.T(lang, "api.passkey_removed_sessions_revoked")})
	}
}

// PasskeyRename updates the friendly name for an existing credential.
func PasskeyRename(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, _ := db.GetGlobalSettings()
		if !globalSettings.TOTPEnabled {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Passkeys are disabled in settings"})
		}
		var body struct {
			Username     string `json:"username"`
			CredentialID string `json:"credential_id"`
			Name         string `json:"name"`
		}
		if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		un := strings.TrimSpace(body.Username)
		if un == "" || !usernameRegexp.MatchString(un) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid username"})
		}
		if !isAdmin(c) && un != currentUser(c) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Not allowed"})
		}
		wantID, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(body.CredentialID))
		if err != nil || len(wantID) == 0 {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Invalid credential id"})
		}
		u, err := db.GetUserByName(un)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "User not found"})
		}
		found := false
		for _, pc := range u.Passkeys {
			if len(pc.ID) > 0 && bytes.Equal(pc.ID, wantID) {
				found = true
				break
			}
		}
		if !found {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{false, "Credential not found"})
		}
		idKey := base64.RawURLEncoding.EncodeToString(wantID)
		if u.PasskeyLabels == nil {
			u.PasskeyLabels = map[string]string{}
		}
		u.PasskeyLabels[idKey] = strings.TrimSpace(body.Name)
		if err := db.SaveUser(u); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		if un == currentUser(c) {
			setUser(c, u.Username, u.Admin, util.GetDBUserCRC32(u))
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Passkey renamed"})
	}
}

const passkeyDiscoverableSessionKey = "passkey_login_discoverable"

// passkeyAssertionAllowList builds allowCredentials for username-based login.
// Credentials registered in some browsers omit transports in storage; Credential Manager on Android then
// may not surface them for synced/platform passkeys unless we widen allowed transports when empty.
func passkeyAssertionAllowList(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	if len(creds) == 0 {
		return nil
	}
	whenEmpty := []protocol.AuthenticatorTransport{
		protocol.Internal,
		protocol.Hybrid,
		protocol.USB,
		protocol.NFC,
		protocol.BLE,
	}
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for i := range creds {
		d := creds[i].Descriptor()
		if len(d.Transport) == 0 {
			d.Transport = whenEmpty
		}
		out = append(out, d)
	}
	return out
}

func discoverableUserLookup(db store.IStore) func(rawID, userHandle []byte) (webauthn.User, error) {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		users, err := db.GetUsers()
		if err != nil {
			return nil, err
		}
		for _, mu := range users {
			for _, pc := range mu.Passkeys {
				if len(pc.ID) > 0 && bytes.Equal(pc.ID, rawID) {
					return webAuthnUser{mu}, nil
				}
			}
		}
		return nil, fmt.Errorf("credential not found")
	}
}

func PasskeyBeginLogin(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, _ := db.GetGlobalSettings()
		if !globalSettings.TOTPEnabled {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Passkeys are disabled"})
		}
		data := make(map[string]interface{})
		if err := c.Bind(&data); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		username, _ := data["username"].(string)
		username = strings.TrimSpace(username)

		wa, err := webauthnForRequest(c)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		sess, _ := session.Get("session", c)
		token := xid.New().String()

		if username == "" {
			// Discoverable / passkey-only login (no username).
			opts, sessionData, err := wa.BeginDiscoverableLogin()
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
			}
			passkeyLoginMu.Lock()
			passkeyLoginSessions[token] = *sessionData
			passkeyLoginMu.Unlock()
			sess.Values[passkeyDiscoverableSessionKey] = token
			_ = sess.Save(c.Request(), c.Response())
			return c.JSON(http.StatusOK, map[string]interface{}{"status": true, "discoverable": true, "options": opts})
		}

		if !usernameRegexp.MatchString(username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}
		u, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Invalid credentials"})
		}
		if len(u.Passkeys) == 0 {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "No passkey registered for this user"})
		}
		opts, sessionData, err := wa.BeginLogin(
			webAuthnUser{u},
			webauthn.WithAllowedCredentials(passkeyAssertionAllowList(u.Passkeys)),
		)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		passkeyLoginMu.Lock()
		passkeyLoginSessions[token] = *sessionData
		passkeyLoginMu.Unlock()
		sess.Values["passkey_login_"+username] = token
		_ = sess.Save(c.Request(), c.Response())
		return c.JSON(http.StatusOK, map[string]interface{}{"status": true, "discoverable": false, "username": username, "options": opts})
	}
}

func PasskeyFinishLogin(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, _ := db.GetGlobalSettings()
		if !globalSettings.TOTPEnabled {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "Passkeys are disabled"})
		}
		// Read body for username/rememberMe, then restore it: c.Bind() would drain the body and
		// wa.FinishLogin would get an empty request → "Parse error for Assertion".
		bodyBytes, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		c.Request().Body = io.NopCloser(bytes.NewReader(bodyBytes))
		var loginMeta struct {
			Username   string `json:"username"`
			RememberMe bool   `json:"rememberMe"`
		}
		if err := json.Unmarshal(bodyBytes, &loginMeta); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Bad post data"})
		}
		username := strings.TrimSpace(loginMeta.Username)
		rememberMe := loginMeta.RememberMe

		wa, err := webauthnForRequest(c)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		sess, _ := session.Get("session", c)

		if username == "" {
			token, _ := sess.Values[passkeyDiscoverableSessionKey].(string)
			if token == "" {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Login session not found"})
			}
			passkeyLoginMu.Lock()
			sessionData, ok := passkeyLoginSessions[token]
			passkeyLoginMu.Unlock()
			if !ok {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Login session expired"})
			}
			wUser, cred, err := wa.FinishPasskeyLogin(discoverableUserLookup(db), sessionData, c.Request())
			if err != nil {
				log.Warnf("[passkeys] discoverable login finish rejected: %v", err)
				return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Invalid passkey"})
			}
			wu, ok := wUser.(webAuthnUser)
			if !ok {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "Invalid user state"})
			}
			u := wu.u
			if u.Disabled {
				return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Cuenta deshabilitada"})
			}
			if err := setLoginSession(c, u, rememberMe, globalSettings.SessionTimeoutMinutes); err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, fmt.Sprintf("Cannot set session: %v", err)})
			}
			freshSess, _ := session.Get("session", c)
			if cred != nil && len(cred.ID) > 0 {
				freshSess.Values[sessionPkLoginCredKey] = base64.RawURLEncoding.EncodeToString(cred.ID)
			}
			delete(freshSess.Values, passkeyDiscoverableSessionKey)
			passkeyLoginMu.Lock()
			delete(passkeyLoginSessions, token)
			passkeyLoginMu.Unlock()
			_ = freshSess.Save(c.Request(), c.Response())
			return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Logged in successfully"})
		}

		if !usernameRegexp.MatchString(username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Please provide a valid username"})
		}
		u, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Invalid credentials"})
		}
		if u.Disabled {
			return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Cuenta deshabilitada"})
		}
		token, _ := sess.Values["passkey_login_"+username].(string)
		if token == "" {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Login session not found"})
		}
		passkeyLoginMu.Lock()
		sessionData, ok := passkeyLoginSessions[token]
		passkeyLoginMu.Unlock()
		if !ok {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "Login session expired"})
		}
		cred, err := wa.FinishLogin(webAuthnUser{u}, sessionData, c.Request())
		if err != nil {
			log.Warnf("[passkeys] login finish rejected for %s: %v", username, err)
			return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{false, "Invalid passkey"})
		}
		if err := setLoginSession(c, u, rememberMe, globalSettings.SessionTimeoutMinutes); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, fmt.Sprintf("Cannot set session: %v", err)})
		}
		freshSess, _ := session.Get("session", c)
		if cred != nil && len(cred.ID) > 0 {
			freshSess.Values[sessionPkLoginCredKey] = base64.RawURLEncoding.EncodeToString(cred.ID)
		}
		delete(freshSess.Values, "passkey_login_"+username)
		passkeyLoginMu.Lock()
		delete(passkeyLoginSessions, token)
		passkeyLoginMu.Unlock()
		_ = freshSess.Save(c.Request(), c.Response())
		return c.JSON(http.StatusOK, jsonHTTPResponse{true, "Logged in successfully"})
	}
}
