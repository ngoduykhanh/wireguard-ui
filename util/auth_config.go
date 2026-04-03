package util

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type AuthMethod string

const (
	AuthMethodLocal  AuthMethod = "local"
	AuthMethodGitHub AuthMethod = "github"
)

const (
	AuthMethodEnvVar             = "WGUI_AUTH_METHOD"
	GitHubClientIDEnvVar         = "WGUI_GITHUB_CLIENT_ID"
	GitHubClientSecretEnvVar     = "WGUI_GITHUB_CLIENT_SECRET"
	GitHubClientSecretFileEnvVar = "WGUI_GITHUB_CLIENT_SECRET_FILE"
	GitHubRedirectURLEnvVar      = "WGUI_GITHUB_REDIRECT_URL"
	GitHubAllowedUsersEnvVar     = "WGUI_GITHUB_ALLOWED_USERS"
	GitHubAllowedOrgsEnvVar      = "WGUI_GITHUB_ALLOWED_ORGS"
	GitHubAdminUsersEnvVar       = "WGUI_GITHUB_ADMIN_USERS"
)

type GitHubAuthConfig struct {
	ClientID         string
	ClientSecret     string
	ClientSecretFile string
	RedirectURL      string
	AllowedUsers     []string
	AllowedOrgs      []string
	AdminUsers       []string
}

func ParseAuthMethod() AuthMethod {
	method := LookupEnvOrString(AuthMethodEnvVar, "local")
	switch strings.ToLower(method) {
	case "github":
		return AuthMethodGitHub
	default:
		return AuthMethodLocal
	}
}

func ParseGitHubAuthConfig() GitHubAuthConfig {
	clientID := LookupEnvOrString(GitHubClientIDEnvVar, "")
	clientSecret := LookupEnvOrString(GitHubClientSecretEnvVar, "")
	clientSecretFile := LookupEnvOrString(GitHubClientSecretFileEnvVar, "")
	redirectURL := LookupEnvOrString(GitHubRedirectURLEnvVar, "")
	allowedUsersRaw := LookupEnvOrString(GitHubAllowedUsersEnvVar, "")
	allowedOrgsRaw := LookupEnvOrString(GitHubAllowedOrgsEnvVar, "")
	adminUsersRaw := LookupEnvOrString(GitHubAdminUsersEnvVar, "")

	var allowedUsers, allowedOrgs, adminUsers []string
	if allowedUsersRaw != "" {
		allowedUsers = NormalizeUsernames(strings.Split(allowedUsersRaw, ","))
	}
	if allowedOrgsRaw != "" {
		allowedOrgs = NormalizeUsernames(strings.Split(allowedOrgsRaw, ","))
	}
	if adminUsersRaw != "" {
		adminUsers = NormalizeUsernames(strings.Split(adminUsersRaw, ","))
	}

	return GitHubAuthConfig{
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		ClientSecretFile: clientSecretFile,
		RedirectURL:      redirectURL,
		AllowedUsers:     allowedUsers,
		AllowedOrgs:      allowedOrgs,
		AdminUsers:       adminUsers,
	}
}

func ValidateGitHubAuthConfig(config GitHubAuthConfig) error {
	if config.ClientID == "" {
		return errors.New("github auth config: client_id is required")
	}

	if config.ClientSecret == "" && config.ClientSecretFile == "" {
		return errors.New("github auth config: client_secret is required")
	}

	if config.ClientSecretFile != "" {
		secret, err := os.ReadFile(config.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("github auth config: reading client_secret_file %q: %w", config.ClientSecretFile, err)
		}
		if len(strings.TrimSpace(string(secret))) == 0 {
			return fmt.Errorf("github auth config: client_secret_file %q is empty", config.ClientSecretFile)
		}
	}

	if config.RedirectURL == "" {
		return errors.New("github auth config: redirect_url is required")
	}

	if len(config.AllowedUsers) == 0 && len(config.AllowedOrgs) == 0 {
		return errors.New("github auth config: at least one of allowed_users or allowed_orgs is required")
	}

	if len(config.AdminUsers) == 0 {
		return errors.New("github auth config: admin_users is required")
	}

	return nil
}

func NormalizeUsernames(users []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(users))
	for _, user := range users {
		normalized := strings.ToLower(strings.TrimSpace(user))
		if normalized != "" && !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result
}
