package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

var (
	GitHubOAuth2Config *oauth2.Config
	GitHubAllowedUsers []string
	GitHubAllowedOrgs  []string
	GitHubAdminUsers   []string
	GitHubUserInfoURL  = "https://api.github.com/user"
	GitHubOrgsURL      = "https://api.github.com/user/memberships/orgs"
)

var githubLoginRegexp = regexp.MustCompile(`^\w[\w\-.]*$`)

var errGitHubUsernameConflict = errors.New("username is already bound to a different GitHub account")

func ApplyGitHubAuthConfig(config util.GitHubAuthConfig) error {
	clientSecret := strings.TrimSpace(config.ClientSecret)
	if clientSecret == "" && config.ClientSecretFile != "" {
		secret, err := os.ReadFile(config.ClientSecretFile)
		if err != nil {
			return err
		}
		clientSecret = strings.TrimSpace(string(secret))
	}

	GitHubOAuth2Config = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{"read:user", "read:org"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}
	GitHubAllowedUsers = append([]string(nil), config.AllowedUsers...)
	GitHubAllowedOrgs = append([]string(nil), config.AllowedOrgs...)
	GitHubAdminUsers = append([]string(nil), config.AdminUsers...)
	return nil
}

type githubUserResponse struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
}

type githubOrgMembership struct {
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
	State string `json:"state"`
}

func GitHubStart() echo.HandlerFunc {
	return func(c echo.Context) error {
		state := generateOAuthState()
		expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()

		next := c.QueryParam("next")
		if next == "" {
			next = "/"
		}
		if !isSafeNextURL(next) {
			next = "/"
		}

		sess, _ := session.Get("session", c)
		sess.Values["oauth_state"] = state
		sess.Values["oauth_state_expires_at"] = expiresAt
		sess.Values["oauth_next"] = next
		sess.Save(c.Request(), c.Response())

		authURL := GitHubOAuth2Config.AuthCodeURL(state, oauth2.AccessTypeOnline)
		return c.Redirect(http.StatusTemporaryRedirect, authURL)
	}
}

func GitHubCallback(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := session.Get("session", c)

		state := c.QueryParam("state")
		expectedState, _ := sess.Values["oauth_state"].(string)
		if state == "" || expectedState == "" || state != expectedState {
			clearOAuthSession(c)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "invalid oauth state"})
		}

		expiresAt, _ := sess.Values["oauth_state_expires_at"].(int64)
		if time.Now().UTC().Unix() > expiresAt {
			clearOAuthSession(c)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "oauth state expired"})
		}

		next, _ := sess.Values["oauth_next"].(string)
		if !isSafeNextURL(next) {
			clearOAuthSession(c)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "invalid redirect target"})
		}

		code := c.QueryParam("code")
		if code == "" {
			clearOAuthSession(c)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "missing authorization code"})
		}

		token, err := GitHubOAuth2Config.Exchange(c.Request().Context(), code)
		if err != nil {
			clearOAuthSession(c)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "failed to exchange code for token"})
		}

		githubUser, err := fetchGitHubUser(token.AccessToken)
		if err != nil {
			clearOAuthSession(c)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "failed to fetch GitHub user"})
		}

		githubLogin := strings.ToLower(githubUser.Login)
		if !isValidGitHubLogin(githubLogin) {
			clearOAuthSession(c)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, "invalid GitHub username"})
		}

		isAllowed := isGitHubUserAllowed(githubLogin, token.AccessToken)
		if !isAllowed {
			clearOAuthSession(c)
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{false, "user not authorized"})
		}

		isAdmin := isGitHubAdmin(githubLogin)

		user, originalUsername, err := findOrMigrateGitHubUser(db, githubLogin, githubUser.ID, githubUser.Name)
		if err != nil {
			clearOAuthSession(c)
			if errors.Is(err, errGitHubUsernameConflict) {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{false, err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "failed to resolve GitHub user"})
		}

		user.Username = githubLogin
		user.DisplayName = githubUser.Name
		user.AuthSource = "github"
		user.AuthSubject = fmt.Sprintf("%d", githubUser.ID)
		user.Password = ""
		user.PasswordHash = ""
		user.Admin = isAdmin

		if originalUsername != "" && originalUsername != githubLogin {
			if err := db.ReplaceUser(originalUsername, *user); err != nil {
				clearOAuthSession(c)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "failed to update user"})
			}
		} else {
			if err := db.SaveUser(*user); err != nil {
				clearOAuthSession(c)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "failed to save user"})
			}
		}

		rememberMe := getSessionRememberMe(sess)

		if err := establishAuthenticatedSession(c, *user, rememberMe); err != nil {
			clearOAuthSession(c)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, "failed to establish session"})
		}

		clearOAuthSession(c)

		return c.Redirect(http.StatusTemporaryRedirect, next)
	}
}

func generateOAuthState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func isSafeNextURL(next string) bool {
	if next == "" {
		return false
	}
	u, err := url.Parse(next)
	if err != nil {
		return false
	}
	if u.Opaque != "" && !strings.HasPrefix(next, "/") {
		return false
	}
	if u.Host != "" {
		return false
	}
	if !strings.HasPrefix(next, "/") {
		return false
	}
	return true
}

func isValidGitHubLogin(login string) bool {
	if login == "" {
		return false
	}
	return githubLoginRegexp.MatchString(login)
}

func isGitHubUserAllowed(login string, accessToken string) bool {
	loginLower := strings.ToLower(login)
	if len(GitHubAllowedUsers) > 0 {
		for _, allowed := range GitHubAllowedUsers {
			if strings.ToLower(allowed) == loginLower {
				return true
			}
		}
	}

	if len(GitHubAllowedOrgs) > 0 {
		orgs, err := fetchGitHubOrgs(accessToken)
		if err == nil {
			for _, org := range orgs {
				for _, allowedOrg := range GitHubAllowedOrgs {
					if strings.ToLower(org) == strings.ToLower(allowedOrg) {
						return true
					}
				}
			}
		}
	}

	return false
}

func isGitHubAdmin(login string) bool {
	loginLower := strings.ToLower(login)
	for _, admin := range GitHubAdminUsers {
		if strings.ToLower(admin) == loginLower {
			return true
		}
	}
	return false
}

func fetchGitHubUser(accessToken string) (*githubUserResponse, error) {
	req, err := http.NewRequest(http.MethodGet, GitHubUserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var user githubUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func fetchGitHubOrgs(accessToken string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, GitHubOrgsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var memberships []githubOrgMembership
	if err := json.NewDecoder(resp.Body).Decode(&memberships); err != nil {
		return nil, err
	}

	var orgs []string
	for _, m := range memberships {
		if m.State == "active" {
			orgs = append(orgs, strings.ToLower(m.Organization.Login))
		}
	}

	return orgs, nil
}

func clearOAuthSession(c echo.Context) {
	sess, _ := session.Get("session", c)
	delete(sess.Values, "oauth_state")
	delete(sess.Values, "oauth_state_expires_at")
	delete(sess.Values, "oauth_next")
	sess.Save(c.Request(), c.Response())
}

func getSessionRememberMe(sess *sessions.Session) bool {
	maxAge, ok := sess.Values["max_age"].(int)
	if !ok {
		return false
	}
	return maxAge > 0
}

func findOrMigrateGitHubUser(db store.IStore, githubLogin string, githubID int64, displayName string) (*model.User, string, error) {
	existingUser, err := db.GetUserByAuthIdentity("github", fmt.Sprintf("%d", githubID))
	if err == nil {
		return &existingUser, existingUser.Username, nil
	}

	localUser, err := db.GetUserByName(githubLogin)
	if err == nil {
		if localUser.AuthSource == "local" && localUser.AuthSubject == "" {
			return &localUser, localUser.Username, nil
		}
		if localUser.AuthSource == "github" && localUser.AuthSubject != "" && localUser.AuthSubject != fmt.Sprintf("%d", githubID) {
			return nil, "", errGitHubUsernameConflict
		}
		return &localUser, localUser.Username, nil
	}

	newUser := model.User{
		Username:    githubLogin,
		DisplayName: displayName,
	}

	return &newUser, "", nil
}
