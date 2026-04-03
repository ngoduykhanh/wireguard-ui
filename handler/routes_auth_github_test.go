package handler

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/util"
	"golang.org/x/oauth2"
)

var (
	githubAPIHandler http.Handler
	githubTokenURL   string
	githubUserURL    string
	githubOrgsURL    string
)

func init() {
	util.SessionMaxDuration = 86400 * 90
	util.DBUsersToCRC32 = map[string]uint32{}
}

func getTestUserCRC32(user model.User) uint32 {
	h := crc32.NewIEEE()
	writeHashField := func(h io.Writer, value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(value))
	}
	writeHashField(h, user.Username)
	if user.Admin {
		writeHashField(h, "1")
	} else {
		writeHashField(h, "0")
	}
	writeHashField(h, user.Password)
	writeHashField(h, user.PasswordHash)
	writeHashField(h, user.AuthSource)
	writeHashField(h, user.AuthSubject)
	return h.Sum32()
}

func setupTestServer() (*httptest.Server, *http.ServeMux) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	githubTokenURL = server.URL + "/oauth/token"
	githubUserURL = server.URL + "/user"
	githubOrgsURL = server.URL + "/user/memberships/orgs"
	return server, mux
}

func setupGitHubAPIHandler(mux *http.ServeMux, userLogin string, userID int64, orgs []string, isOrgMember bool) {
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.FormValue("grant_type") != "authorization_code" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"scope":        "read:user,user:email",
		})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"login": userLogin,
			"id":    userID,
			"name":  "Test User",
		})
	})
	mux.HandleFunc("/user/memberships/orgs", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if isOrgMember {
			var orgsData []map[string]interface{}
			for _, org := range orgs {
				orgsData = append(orgsData, map[string]interface{}{
					"organization": map[string]interface{}{
						"login": org,
					},
					"state": "active",
				})
			}
			json.NewEncoder(w).Encode(orgsData)
		} else {
			json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	})
}

func TestApplyGitHubAuthConfig_SetsRuntimeGlobals(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "github-secret")
	if err := os.WriteFile(secretFile, []byte("test-secret"), 0600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	config := util.GitHubAuthConfig{
		ClientID:         "client-id",
		ClientSecretFile: secretFile,
		RedirectURL:      "https://example.com/auth/github/callback",
		AllowedUsers:     []string{"user1"},
		AllowedOrgs:      []string{"org1"},
		AdminUsers:       []string{"admin1"},
	}

	if err := ApplyGitHubAuthConfig(config); err != nil {
		t.Fatalf("expected ApplyGitHubAuthConfig to succeed, got %v", err)
	}

	if GitHubOAuth2Config == nil {
		t.Fatal("expected GitHubOAuth2Config to be initialized")
	}
	if GitHubOAuth2Config.ClientID != "client-id" {
		t.Fatalf("expected client id to be bridged, got %q", GitHubOAuth2Config.ClientID)
	}
	if GitHubOAuth2Config.ClientSecret != "test-secret" {
		t.Fatalf("expected client secret to be loaded from file, got %q", GitHubOAuth2Config.ClientSecret)
	}
	if GitHubOAuth2Config.RedirectURL != "https://example.com/auth/github/callback" {
		t.Fatalf("expected redirect url to be bridged, got %q", GitHubOAuth2Config.RedirectURL)
	}
	if len(GitHubAllowedUsers) != 1 || GitHubAllowedUsers[0] != "user1" {
		t.Fatalf("expected allowed users to be bridged, got %#v", GitHubAllowedUsers)
	}
	if len(GitHubAllowedOrgs) != 1 || GitHubAllowedOrgs[0] != "org1" {
		t.Fatalf("expected allowed orgs to be bridged, got %#v", GitHubAllowedOrgs)
	}
	if len(GitHubAdminUsers) != 1 || GitHubAdminUsers[0] != "admin1" {
		t.Fatalf("expected admin users to be bridged, got %#v", GitHubAdminUsers)
	}
	if GitHubOAuth2Config.Endpoint.AuthURL == "" || GitHubOAuth2Config.Endpoint.TokenURL == "" {
		t.Fatal("expected GitHub OAuth endpoints to be initialized")
	}
	if len(GitHubOAuth2Config.Scopes) != 2 || GitHubOAuth2Config.Scopes[0] != "read:user" || GitHubOAuth2Config.Scopes[1] != "read:org" {
		t.Fatalf("expected GitHub OAuth scopes to be initialized, got %#v", GitHubOAuth2Config.Scopes)
	}
}

type testApp struct {
	E           *echo.Echo
	CookieStore *sessions.CookieStore
}

func newTestApp() *testApp {
	e := echo.New()
	secret := make([]byte, 64)
	rand.Read(secret)
	cookieStore := sessions.NewCookieStore(secret[:32], secret[32:])
	cookieStore.Options.Path = "/"
	cookieStore.Options.HttpOnly = true
	cookieStore.MaxAge(86400 * 7)
	e.Use(session.Middleware(cookieStore))
	return &testApp{E: e, CookieStore: cookieStore}
}

func newTestAppWithFixedSecret() *testApp {
	e := echo.New()
	secret, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	cookieStore := sessions.NewCookieStore(secret[:32], secret[32:])
	cookieStore.Options.Path = "/"
	cookieStore.Options.HttpOnly = true
	cookieStore.MaxAge(86400 * 7)
	e.Use(session.Middleware(cookieStore))
	return &testApp{E: e, CookieStore: cookieStore}
}

type mockStore struct {
	users        []model.User
	savedUsers   map[string]model.User
	deletedUsers []string
}

func (m *mockStore) Init() error                     { return nil }
func (m *mockStore) GetUsers() ([]model.User, error) { return m.users, nil }
func (m *mockStore) GetUserByName(username string) (model.User, error) {
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return model.User{}, fmt.Errorf("not found")
}
func (m *mockStore) GetUserByAuthIdentity(authSource, authSubject string) (model.User, error) {
	for _, u := range m.users {
		if u.AuthSource == authSource && u.AuthSubject == authSubject {
			return u, nil
		}
	}
	return model.User{}, fmt.Errorf("not found")
}
func (m *mockStore) SaveUser(user model.User) error {
	if m.savedUsers == nil {
		m.savedUsers = make(map[string]model.User)
	}
	m.savedUsers[user.Username] = user
	for i, u := range m.users {
		if u.Username == user.Username {
			m.users[i] = user
			return nil
		}
	}
	m.users = append(m.users, user)
	return nil
}
func (m *mockStore) ReplaceUser(oldUsername string, user model.User) error {
	return m.SaveUser(user)
}
func (m *mockStore) DeleteUser(username string) error {
	m.deletedUsers = append(m.deletedUsers, username)
	return nil
}
func (m *mockStore) GetGlobalSettings() (model.GlobalSetting, error) {
	return model.GlobalSetting{}, nil
}
func (m *mockStore) GetServer() (model.Server, error)            { return model.Server{}, nil }
func (m *mockStore) GetClients(bool) ([]model.ClientData, error) { return nil, nil }
func (m *mockStore) GetClientByID(string, model.QRCodeSettings) (model.ClientData, error) {
	return model.ClientData{}, nil
}
func (m *mockStore) SaveClient(model.Client) error                         { return nil }
func (m *mockStore) DeleteClient(string) error                             { return nil }
func (m *mockStore) SaveServerInterface(model.ServerInterface) error       { return nil }
func (m *mockStore) SaveServerKeyPair(model.ServerKeypair) error           { return nil }
func (m *mockStore) SaveGlobalSettings(model.GlobalSetting) error          { return nil }
func (m *mockStore) GetWakeOnLanHosts() ([]model.WakeOnLanHost, error)     { return nil, nil }
func (m *mockStore) GetWakeOnLanHost(string) (*model.WakeOnLanHost, error) { return nil, nil }
func (m *mockStore) DeleteWakeOnHostLanHost(string) error                  { return nil }
func (m *mockStore) SaveWakeOnLanHost(model.WakeOnLanHost) error           { return nil }
func (m *mockStore) DeleteWakeOnHost(model.WakeOnLanHost) error            { return nil }
func (m *mockStore) GetPath() string                                       { return "" }
func (m *mockStore) SaveHashes(model.ClientServerHashes) error             { return nil }
func (m *mockStore) GetHashes() (model.ClientServerHashes, error) {
	return model.ClientServerHashes{}, nil
}

func TestGitHubCallback_AllowsWhitelistedUser(t *testing.T) {
	server, mux := setupTestServer()
	defer server.Close()
	setupGitHubAPIHandler(mux, "whitelistuser", 1001, nil, false)

	GitHubOAuth2Config = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/oauth/authorize",
			TokenURL: githubTokenURL,
		},
	}
	GitHubAllowedUsers = []string{"whitelistuser"}
	GitHubAllowedOrgs = []string{}
	GitHubAdminUsers = []string{"admin"}

	GitHubUserInfoURL = githubUserURL
	GitHubOrgsURL = githubOrgsURL

	mockDB := &mockStore{}
	app := newTestApp()

	state := generateOAuthState()
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

	app.E.POST("/github/start", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		sess.Values["oauth_state"] = state
		sess.Values["oauth_state_expires_at"] = expiresAt
		sess.Values["oauth_next"] = "/"
		sess.Save(c.Request(), c.Response())
		return c.NoContent(http.StatusOK)
	})
	app.E.GET("/github/callback", GitHubCallback(mockDB))

	req := httptest.NewRequest(http.MethodPost, "/github/start", nil)
	rec := httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("start handler failed: %d", rec.Code)
	}

	cookies := rec.Result().Cookies()

	req = httptest.NewRequest(http.MethodGet, "/github/callback?code=test-code&state="+state, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected redirect 307, got %d. body: %s, location: %s", rec.Code, rec.Body.String(), rec.Header().Get("Location"))
	}

	if rec.Header().Get("Location") != "/" {
		t.Errorf("expected redirect to '/', got '%s'", rec.Header().Get("Location"))
	}

	sessionCookies := rec.Result().Cookies()
	var sessionToken string
	for _, c := range sessionCookies {
		if c.Name == "session_token" {
			sessionToken = c.Value
			break
		}
	}
	if sessionToken == "" {
		t.Fatal("expected session_token cookie to be set")
	}

	savedUser, ok := mockDB.savedUsers["whitelistuser"]
	if !ok {
		t.Fatal("expected user to be saved to store")
	}
	if savedUser.AuthSource != "github" {
		t.Errorf("expected AuthSource 'github', got '%s'", savedUser.AuthSource)
	}
	if savedUser.AuthSubject != "1001" {
		t.Errorf("expected AuthSubject '1001', got '%s'", savedUser.AuthSubject)
	}
	if savedUser.Password != "" {
		t.Errorf("expected empty Password, got '%s'", savedUser.Password)
	}
	if savedUser.PasswordHash != "" {
		t.Errorf("expected empty PasswordHash, got '%s'", savedUser.PasswordHash)
	}
	if savedUser.Admin {
		t.Errorf("expected Admin false, got true")
	}
}

func TestGitHubCallback_AllowsOrgMember(t *testing.T) {
	server, mux := setupTestServer()
	defer server.Close()
	setupGitHubAPIHandler(mux, "orgmember", 1002, []string{"allowed-org"}, true)

	GitHubOAuth2Config = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/oauth/authorize",
			TokenURL: githubTokenURL,
		},
	}
	GitHubAllowedUsers = []string{}
	GitHubAllowedOrgs = []string{"allowed-org"}
	GitHubAdminUsers = []string{"admin"}

	GitHubUserInfoURL = githubUserURL
	GitHubOrgsURL = githubOrgsURL

	mockDB := &mockStore{}
	app := newTestApp()

	state := generateOAuthState()
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

	app.E.POST("/github/start", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		sess.Values["oauth_state"] = state
		sess.Values["oauth_state_expires_at"] = expiresAt
		sess.Values["oauth_next"] = "/"
		sess.Save(c.Request(), c.Response())
		return c.NoContent(http.StatusOK)
	})
	app.E.GET("/github/callback", GitHubCallback(mockDB))

	req := httptest.NewRequest(http.MethodPost, "/github/start", nil)
	rec := httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("start handler failed: %d", rec.Code)
	}

	cookies := rec.Result().Cookies()

	req = httptest.NewRequest(http.MethodGet, "/github/callback?code=test-code&state="+state, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected redirect 307, got %d", rec.Code)
	}
}

func TestGitHubCallback_RejectsStateMismatch(t *testing.T) {
	server, _ := setupTestServer()
	defer server.Close()

	GitHubOAuth2Config = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/oauth/authorize",
			TokenURL: githubTokenURL,
		},
	}
	GitHubAllowedUsers = []string{"testuser"}
	GitHubAllowedOrgs = []string{}
	GitHubAdminUsers = []string{"admin"}

	mockDB := &mockStore{}
	app := newTestApp()

	app.E.GET("/github/callback", GitHubCallback(mockDB))

	state := generateOAuthState()
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

	app.E.POST("/github/start", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		sess.Values["oauth_state"] = state
		sess.Values["oauth_state_expires_at"] = expiresAt
		sess.Values["oauth_next"] = "/"
		sess.Save(c.Request(), c.Response())
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/github/start", nil)
	rec := httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()

	req = httptest.NewRequest(http.MethodGet, "/github/callback?code=test-code&state=wrong-state", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestGitHubCallback_RejectsExpiredState(t *testing.T) {
	server, _ := setupTestServer()
	defer server.Close()

	GitHubOAuth2Config = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/oauth/authorize",
			TokenURL: githubTokenURL,
		},
	}
	GitHubAllowedUsers = []string{"testuser"}
	GitHubAllowedOrgs = []string{}
	GitHubAdminUsers = []string{"admin"}

	mockDB := &mockStore{}
	app := newTestApp()

	state := generateOAuthState()

	app.E.POST("/github/start", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		sess.Values["oauth_state"] = state
		sess.Values["oauth_state_expires_at"] = time.Now().UTC().Add(-1 * time.Minute).Unix()
		sess.Values["oauth_next"] = "/"
		sess.Save(c.Request(), c.Response())
		return c.NoContent(http.StatusOK)
	})
	app.E.GET("/github/callback", GitHubCallback(mockDB))

	req := httptest.NewRequest(http.MethodPost, "/github/start", nil)
	rec := httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()

	req = httptest.NewRequest(http.MethodGet, "/github/callback?code=test-code&state="+state, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestGitHubCallback_RejectsExternalNextURL(t *testing.T) {
	server, _ := setupTestServer()
	defer server.Close()

	GitHubOAuth2Config = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/oauth/authorize",
			TokenURL: githubTokenURL,
		},
	}
	GitHubAllowedUsers = []string{"testuser"}
	GitHubAllowedOrgs = []string{}
	GitHubAdminUsers = []string{"admin"}

	mockDB := &mockStore{}
	app := newTestApp()

	state := generateOAuthState()
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

	app.E.POST("/github/start", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		sess.Values["oauth_state"] = state
		sess.Values["oauth_state_expires_at"] = expiresAt
		sess.Values["oauth_next"] = "http://evil.com/redirect"
		sess.Save(c.Request(), c.Response())
		return c.NoContent(http.StatusOK)
	})
	app.E.GET("/github/callback", GitHubCallback(mockDB))

	req := httptest.NewRequest(http.MethodPost, "/github/start", nil)
	rec := httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()

	req = httptest.NewRequest(http.MethodGet, "/github/callback?code=test-code&state="+state, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestGitHubCallback_RejectsUnsafeGitHubLogin(t *testing.T) {
	unsafeLogins := []string{
		"user with space",
		"user\nwith\nnewline",
		"",
		"-invalid",
	}

	for _, unsafeLogin := range unsafeLogins {
		server, mux := setupTestServer()
		setupGitHubAPIHandler(mux, unsafeLogin, 1001, nil, false)

		GitHubOAuth2Config = &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/github/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL + "/oauth/authorize",
				TokenURL: githubTokenURL,
			},
		}
		GitHubAllowedUsers = []string{strings.ToLower(unsafeLogin)}
		GitHubAllowedOrgs = []string{}
		GitHubAdminUsers = []string{"admin"}

		GitHubUserInfoURL = githubUserURL
		GitHubOrgsURL = githubOrgsURL

		mockDB := &mockStore{}
		app := newTestApp()

		state := generateOAuthState()
		expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

		app.E.POST("/github/start", func(c echo.Context) error {
			sess, _ := session.Get("session", c)
			sess.Values["oauth_state"] = state
			sess.Values["oauth_state_expires_at"] = expiresAt
			sess.Values["oauth_next"] = "/"
			sess.Save(c.Request(), c.Response())
			return c.NoContent(http.StatusOK)
		})
		app.E.GET("/github/callback", GitHubCallback(mockDB))

		req := httptest.NewRequest(http.MethodPost, "/github/start", nil)
		rec := httptest.NewRecorder()
		app.E.ServeHTTP(rec, req)

		cookies := rec.Result().Cookies()

		req = httptest.NewRequest(http.MethodGet, "/github/callback?code=test-code&state="+state, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec = httptest.NewRecorder()
		app.E.ServeHTTP(rec, req)
		server.Close()

		if rec.Code != http.StatusBadRequest {
			t.Errorf("login %q: expected status 400, got %d", unsafeLogin, rec.Code)
		}
	}
}

func TestGitHubCallback_MigratesLegacyLocalUser(t *testing.T) {
	server, mux := setupTestServer()
	defer server.Close()
	setupGitHubAPIHandler(mux, "legacyuser", 1001, nil, false)

	GitHubOAuth2Config = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/oauth/authorize",
			TokenURL: githubTokenURL,
		},
	}
	GitHubAllowedUsers = []string{"legacyuser"}
	GitHubAllowedOrgs = []string{}
	GitHubAdminUsers = []string{"admin"}

	GitHubUserInfoURL = githubUserURL
	GitHubOrgsURL = githubOrgsURL

	mockDB := &mockStore{
		users: []model.User{
			{
				Username:     "legacyuser",
				Password:     "legacy-pass",
				PasswordHash: "",
				AuthSource:   "local",
				AuthSubject:  "",
				Admin:        false,
			},
		},
	}
	app := newTestApp()

	state := generateOAuthState()
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

	app.E.POST("/github/start", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		sess.Values["oauth_state"] = state
		sess.Values["oauth_state_expires_at"] = expiresAt
		sess.Values["oauth_next"] = "/"
		sess.Save(c.Request(), c.Response())
		return c.NoContent(http.StatusOK)
	})
	app.E.GET("/github/callback", GitHubCallback(mockDB))

	req := httptest.NewRequest(http.MethodPost, "/github/start", nil)
	rec := httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("start handler failed: %d", rec.Code)
	}

	cookies := rec.Result().Cookies()

	req = httptest.NewRequest(http.MethodGet, "/github/callback?code=test-code&state="+state, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected redirect 307, got %d", rec.Code)
	}

	savedUser, ok := mockDB.savedUsers["legacyuser"]
	if !ok {
		t.Fatal("expected user to be saved to store")
	}
	if savedUser.AuthSource != "github" {
		t.Errorf("expected AuthSource 'github', got '%s'", savedUser.AuthSource)
	}
	if savedUser.AuthSubject != "1001" {
		t.Errorf("expected AuthSubject '1001', got '%s'", savedUser.AuthSubject)
	}
	if savedUser.Password != "" {
		t.Errorf("expected empty Password, got '%s'", savedUser.Password)
	}
	if savedUser.PasswordHash != "" {
		t.Errorf("expected empty PasswordHash, got '%s'", savedUser.PasswordHash)
	}
	if savedUser.DisplayName != "Test User" {
		t.Errorf("expected DisplayName 'Test User', got '%s'", savedUser.DisplayName)
	}
}

func TestGitHubCallback_RejectsConflictingBoundUser(t *testing.T) {
	server, mux := setupTestServer()
	defer server.Close()
	setupGitHubAPIHandler(mux, "anotheruser", 1002, nil, false)

	GitHubOAuth2Config = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/oauth/authorize",
			TokenURL: githubTokenURL,
		},
	}
	GitHubAllowedUsers = []string{"anotheruser"}
	GitHubAllowedOrgs = []string{}
	GitHubAdminUsers = []string{"admin"}

	GitHubUserInfoURL = githubUserURL
	GitHubOrgsURL = githubOrgsURL

	mockDB := &mockStore{
		users: []model.User{
			{
				Username:     "anotheruser",
				Password:     "local-pass",
				PasswordHash: "",
				AuthSource:   "github",
				AuthSubject:  "999999",
				Admin:        false,
			},
		},
	}
	app := newTestApp()

	state := generateOAuthState()
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

	app.E.POST("/github/start", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		sess.Values["oauth_state"] = state
		sess.Values["oauth_state_expires_at"] = expiresAt
		sess.Values["oauth_next"] = "/"
		sess.Save(c.Request(), c.Response())
		return c.NoContent(http.StatusOK)
	})
	app.E.GET("/github/callback", GitHubCallback(mockDB))

	req := httptest.NewRequest(http.MethodPost, "/github/start", nil)
	rec := httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()

	req = httptest.NewRequest(http.MethodGet, "/github/callback?code=test-code&state="+state, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	if len(mockDB.savedUsers) > 0 {
		t.Errorf("expected no user to be saved, got %d saved users", len(mockDB.savedUsers))
	}
}

func TestLocalLoginAndGitHubLoginShareSessionBuilder(t *testing.T) {
	testUser := model.User{
		Username:     "testuser",
		Password:     "testpass",
		PasswordHash: "",
		AuthSource:   "local",
		AuthSubject:  "",
		Admin:        true,
	}
	util.DBUsersToCRC32["testuser"] = getTestUserCRC32(testUser)

	mockDB := &mockStore{
		users: []model.User{testUser},
	}

	app := newTestAppWithFixedSecret()
	app.E.POST("/login", Login(mockDB), ContentTypeJson)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"testuser","password":"testpass","rememberMe":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.E.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. body: %s", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	var sessionToken string
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session_token" {
			sessionToken = c.Value
			sessionCookie = c
			break
		}
	}
	if sessionToken == "" {
		t.Fatal("expected session_token cookie to be set")
	}

	if sessionCookie == nil {
		t.Fatal("expected session_token cookie to be set")
	}
	if sessionCookie.Value == "" {
		t.Fatal("expected session_token cookie value to be non-empty")
	}
	if sessionCookie.MaxAge == 0 {
		t.Fatal("expected session_token cookie MaxAge to be set for rememberMe=true")
	}

	req = httptest.NewRequest(http.MethodGet, "/profile", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()

	profileCalled := false
	var profileUsername string
	var profileAdmin interface{}
	app.E.GET("/profile", func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		profileCalled = true
		if sess != nil {
			profileUsername, _ = sess.Values["username"].(string)
			profileAdmin = sess.Values["admin"]
		}
		return c.NoContent(http.StatusOK)
	}, ValidSession, RefreshSession)
	app.E.ServeHTTP(rec, req)

	if !profileCalled {
		t.Fatal("profile handler was not called")
	}

	if profileUsername != "testuser" {
		t.Errorf("expected username 'testuser', got '%v'", profileUsername)
	}

	if profileAdmin != true {
		t.Errorf("expected admin true, got '%v'", profileAdmin)
	}

	if sessionCookie.Value != sessionToken {
		t.Errorf("expected cookie value '%s', got '%s'", sessionToken, sessionCookie.Value)
	}
	if sessionCookie.MaxAge != 86400*7 {
		t.Errorf("expected cookie MaxAge %d, got %d", 86400*7, sessionCookie.MaxAge)
	}
}

var _ = regexp.MustCompile("")
