package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAuthMethod_DefaultLocal(t *testing.T) {
	t.Setenv("WGUI_AUTH_METHOD", "")
	method := ParseAuthMethod()
	if method != AuthMethodLocal {
		t.Errorf("expected default auth method to be %q, got %q", AuthMethodLocal, method)
	}
}

func TestParseAuthMethod_LocalExplicit(t *testing.T) {
	t.Setenv("WGUI_AUTH_METHOD", "local")
	method := ParseAuthMethod()
	if method != AuthMethodLocal {
		t.Errorf("expected auth method to be %q, got %q", AuthMethodLocal, method)
	}
}

func TestParseAuthMethod_GitHubExplicit(t *testing.T) {
	t.Setenv("WGUI_AUTH_METHOD", "github")
	method := ParseAuthMethod()
	if method != AuthMethodGitHub {
		t.Errorf("expected auth method to be %q, got %q", AuthMethodGitHub, method)
	}
}

func TestParseAuthMethod_GitHubCaseInsensitive(t *testing.T) {
	t.Setenv("WGUI_AUTH_METHOD", "GitHub")
	method := ParseAuthMethod()
	if method != AuthMethodGitHub {
		t.Errorf("expected case-insensitive auth method to be %q, got %q", AuthMethodGitHub, method)
	}
}

func TestParseGitHubAuthConfig_NormalizesLists(t *testing.T) {
	t.Setenv("WGUI_GITHUB_CLIENT_ID", "test-client-id")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "test-secret")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET_FILE", "")
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "http://localhost:8080/callback")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", " User1 ,user1, USER2 ")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", " OrgA ,orga ")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", " Admin1 , admin1 ")

	config := ParseGitHubAuthConfig()

	if config.ClientID != "test-client-id" {
		t.Fatalf("expected client_id to be parsed, got %q", config.ClientID)
	}
	if config.ClientSecret != "test-secret" {
		t.Fatalf("expected client_secret to be parsed, got %q", config.ClientSecret)
	}
	if config.RedirectURL != "http://localhost:8080/callback" {
		t.Fatalf("expected redirect_url to be parsed, got %q", config.RedirectURL)
	}

	expectedUsers := []string{"user1", "user2"}
	if len(config.AllowedUsers) != len(expectedUsers) {
		t.Fatalf("expected %d allowed users, got %d", len(expectedUsers), len(config.AllowedUsers))
	}
	for i, user := range expectedUsers {
		if config.AllowedUsers[i] != user {
			t.Fatalf("expected allowed_users[%d]=%q, got %q", i, user, config.AllowedUsers[i])
		}
	}

	expectedOrgs := []string{"orga"}
	if len(config.AllowedOrgs) != len(expectedOrgs) {
		t.Fatalf("expected %d allowed orgs, got %d", len(expectedOrgs), len(config.AllowedOrgs))
	}
	for i, org := range expectedOrgs {
		if config.AllowedOrgs[i] != org {
			t.Fatalf("expected allowed_orgs[%d]=%q, got %q", i, org, config.AllowedOrgs[i])
		}
	}

	expectedAdmins := []string{"admin1"}
	if len(config.AdminUsers) != len(expectedAdmins) {
		t.Fatalf("expected %d admin users, got %d", len(expectedAdmins), len(config.AdminUsers))
	}
	for i, admin := range expectedAdmins {
		if config.AdminUsers[i] != admin {
			t.Fatalf("expected admin_users[%d]=%q, got %q", i, admin, config.AdminUsers[i])
		}
	}
}

func TestValidateGitHubAuthConfig_MissingClientID(t *testing.T) {
	t.Setenv("WGUI_GITHUB_CLIENT_ID", "")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET_FILE", "")
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", "")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", "")

	config := GitHubAuthConfig{}
	err := ValidateGitHubAuthConfig(config)
	if err == nil {
		t.Error("expected error for missing client_id, got nil")
	}
}

func TestValidateGitHubAuthConfig_MissingClientSecret(t *testing.T) {
	t.Setenv("WGUI_GITHUB_CLIENT_ID", "test-client-id")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET_FILE", "")
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", "")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", "")

	config := GitHubAuthConfig{
		ClientID: "test-client-id",
	}
	err := ValidateGitHubAuthConfig(config)
	if err == nil {
		t.Error("expected error for missing client_secret and client_secret_file, got nil")
	}
}

func TestValidateGitHubAuthConfig_MissingClientSecretFile(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	os.WriteFile(secretFile, []byte("test-secret"), 0600)

	t.Setenv("WGUI_GITHUB_CLIENT_ID", "test-client-id")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET_FILE", secretFile)
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", "")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", "")

	config := GitHubAuthConfig{
		ClientID:         "test-client-id",
		ClientSecretFile: secretFile,
	}
	err := ValidateGitHubAuthConfig(config)
	if err == nil {
		t.Error("expected error for missing client_secret and client_secret_file with no readable content, got nil")
	}
}

func TestValidateGitHubAuthConfig_ClientSecretFileReadError(t *testing.T) {
	nonExistentFile := "/nonexistent/path/to/secret"

	t.Setenv("WGUI_GITHUB_CLIENT_ID", "test-client-id")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET_FILE", nonExistentFile)
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", "")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", "")

	config := GitHubAuthConfig{
		ClientID:         "test-client-id",
		ClientSecretFile: nonExistentFile,
	}
	err := ValidateGitHubAuthConfig(config)
	if err == nil {
		t.Error("expected error for unreadable client_secret_file, got nil")
	}
}

func TestValidateGitHubAuthConfig_MissingRedirectURL(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	os.WriteFile(secretFile, []byte("test-secret"), 0600)

	t.Setenv("WGUI_GITHUB_CLIENT_ID", "test-client-id")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "test-secret")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET_FILE", "")
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", "")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", "")

	config := GitHubAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
	}
	err := ValidateGitHubAuthConfig(config)
	if err == nil {
		t.Error("expected error for missing redirect_url, got nil")
	}
}

func TestValidateGitHubAuthConfig_MissingAllowRules(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	os.WriteFile(secretFile, []byte("test-secret"), 0600)

	t.Setenv("WGUI_GITHUB_CLIENT_ID", "test-client-id")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "test-secret")
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "http://localhost:8080/callback")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", "")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", "")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", "")

	config := GitHubAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost:8080/callback",
	}
	err := ValidateGitHubAuthConfig(config)
	if err == nil {
		t.Error("expected error for missing allow rules (allowed_users or allowed_orgs), got nil")
	}
}

func TestValidateGitHubAuthConfig_MissingAdminUsers(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	os.WriteFile(secretFile, []byte("test-secret"), 0600)

	t.Setenv("WGUI_GITHUB_CLIENT_ID", "test-client-id")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "test-secret")
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "http://localhost:8080/callback")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", "user1,user2")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", "")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", "")

	config := GitHubAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost:8080/callback",
		AllowedUsers: []string{"user1", "user2"},
		AllowedOrgs:  []string{},
	}
	err := ValidateGitHubAuthConfig(config)
	if err == nil {
		t.Error("expected error for missing admin_users, got nil")
	}
}

func TestValidateGitHubAuthConfig_ValidMinimal(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	os.WriteFile(secretFile, []byte("test-secret"), 0600)

	t.Setenv("WGUI_GITHUB_CLIENT_ID", "test-client-id")
	t.Setenv("WGUI_GITHUB_CLIENT_SECRET", "test-secret")
	t.Setenv("WGUI_GITHUB_REDIRECT_URL", "http://localhost:8080/callback")
	t.Setenv("WGUI_GITHUB_ALLOWED_USERS", "user1,user2")
	t.Setenv("WGUI_GITHUB_ALLOWED_ORGS", "")
	t.Setenv("WGUI_GITHUB_ADMIN_USERS", "admin1")

	config := GitHubAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost:8080/callback",
		AllowedUsers: []string{"user1", "user2"},
		AdminUsers:   []string{"admin1"},
	}
	err := ValidateGitHubAuthConfig(config)
	if err != nil {
		t.Errorf("expected no error for valid config, got %v", err)
	}
}

func TestNormalizeUsernames_LowercaseAndTrim(t *testing.T) {
	input := []string{" User1 ", "USER2", " user3 "}
	expected := []string{"user1", "user2", "user3"}
	result := NormalizeUsernames(input)
	if len(result) != len(expected) {
		t.Fatalf("expected length %d, got %d", len(expected), len(result))
	}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("expected[%d]=%q, got[%d]=%q", i, expected[i], i, v)
		}
	}
}

func TestNormalizeUsernames_Deduplicate(t *testing.T) {
	input := []string{"User1", "user1", "USER1", "User2"}
	expected := []string{"user1", "user2"}
	result := NormalizeUsernames(input)
	if len(result) != len(expected) {
		t.Fatalf("expected length %d, got %d", len(expected), len(result))
	}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("expected[%d]=%q, got[%d]=%q", i, expected[i], i, v)
		}
	}
}

func TestNormalizeUsernames_Empty(t *testing.T) {
	input := []string{}
	expected := []string{}
	result := NormalizeUsernames(input)
	if len(result) != len(expected) {
		t.Fatalf("expected length %d, got %d", len(expected), len(result))
	}
}

func TestNormalizeUsernames_BlankEntriesDropped(t *testing.T) {
	result := NormalizeUsernames([]string{"", "   ", " user1 "})
	if len(result) != 1 || result[0] != "user1" {
		t.Fatalf("expected blank entries to be dropped, got %#v", result)
	}
}
