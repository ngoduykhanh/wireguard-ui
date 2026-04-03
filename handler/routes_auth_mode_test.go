package handler

import (
	"os"
	"strings"
	"testing"

	"github.com/ngoduykhanh/wireguard-ui/util"
)

func TestLoginPage_GitHubModeShowsOAuthButton(t *testing.T) {
	content, err := os.ReadFile("../templates/login.html")
	if err != nil {
		t.Fatalf("failed to read login.html: %v", err)
	}
	body := string(content)

	if !strings.Contains(body, "auth/github/start") {
		t.Errorf("expected login page to contain 'auth/github/start' in github mode")
	}

	if !strings.Contains(body, ".authMethod") {
		t.Errorf("expected login page to use .authMethod for mode switching")
	}

	if !strings.Contains(body, "btn-github") && !strings.Contains(body, "github-login") {
		t.Errorf("expected login page to have GitHub login button")
	}
}

func TestLoginPage_LocalModeKeepsPasswordForm(t *testing.T) {
	content, err := os.ReadFile("../templates/login.html")
	if err != nil {
		t.Fatalf("failed to read login.html: %v", err)
	}
	body := string(content)

	if !strings.Contains(body, `id="username"`) {
		t.Errorf("expected login page to contain username input in local mode")
	}

	if !strings.Contains(body, `id="password"`) {
		t.Errorf("expected login page to contain password input in local mode")
	}
}

func TestLoginPage_GitHubModeWithNextParam(t *testing.T) {
	content, err := os.ReadFile("../templates/login.html")
	if err != nil {
		t.Fatalf("failed to read login.html: %v", err)
	}
	body := string(content)

	if !strings.Contains(body, "{{if .authMethod}}") && !strings.Contains(body, ".authMethod") {
		t.Errorf("expected login page to use .authMethod to conditionally show OAuth button")
	}

	if !strings.Contains(body, "auth/github/start") {
		t.Errorf("expected login page to contain 'auth/github/start' for OAuth flow")
	}
}

func TestLoginPage_GitHubModeDoesNotShowPasswordForm(t *testing.T) {
	content, err := os.ReadFile("../templates/login.html")
	if err != nil {
		t.Fatalf("failed to read login.html: %v", err)
	}
	body := string(content)

	lines := strings.Split(body, "\n")
	inGitHubBlock := false
	hasPasswordInGitHubBlock := false

	for _, line := range lines {
		if strings.Contains(line, "{{if eq .authMethod \"github\"}}") {
			inGitHubBlock = true
		}
		if inGitHubBlock && strings.Contains(line, "{{else}}") {
			inGitHubBlock = false
		}
		if inGitHubBlock && strings.Contains(line, `id="password"`) {
			hasPasswordInGitHubBlock = true
			break
		}
	}

	if hasPasswordInGitHubBlock {
		t.Errorf("expected password input NOT to be in github mode block")
	}
}

func TestGitHubModeUsersSettingsNotRegistered(t *testing.T) {
	content, err := os.ReadFile("../main.go")
	if err != nil {
		t.Fatalf("failed to read main.go: %v", err)
	}
	body := string(content)

	lines := strings.Split(body, "\n")
	inGitHubBlock := false
	hasUsersSettingsInGitHubBlock := false

	for _, line := range lines {
		if strings.Contains(line, "AuthMethodGitHub") {
			inGitHubBlock = true
		}
		if inGitHubBlock && strings.Contains(line, "} else {") {
			inGitHubBlock = false
			break
		}
		if inGitHubBlock && strings.Contains(line, "users-settings") {
			hasUsersSettingsInGitHubBlock = true
			break
		}
	}

	if hasUsersSettingsInGitHubBlock {
		t.Errorf("users-settings route should not be registered in github mode block")
	}
}

func TestGitHubStartHandlerRegistered(t *testing.T) {
	content, err := os.ReadFile("../main.go")
	if err != nil {
		t.Fatalf("failed to read main.go: %v", err)
	}
	body := string(content)

	if !strings.Contains(body, "auth/github/start") {
		t.Errorf("main.go should register auth/github/start route for github mode")
	}

	if !strings.Contains(body, "GitHubStart") {
		t.Errorf("main.go should use GitHubStart handler")
	}
}

func TestGitHubCallbackHandlerRegistered(t *testing.T) {
	content, err := os.ReadFile("../main.go")
	if err != nil {
		t.Fatalf("failed to read main.go: %v", err)
	}
	body := string(content)

	if !strings.Contains(body, "auth/github/callback") {
		t.Errorf("main.go should register auth/github/callback route for github mode")
	}

	if !strings.Contains(body, "GitHubCallback") {
		t.Errorf("main.go should use GitHubCallback handler")
	}
}

func TestGitHubModeProfileAPIRegistered(t *testing.T) {
	content, err := os.ReadFile("../main.go")
	if err != nil {
		t.Fatalf("failed to read main.go: %v", err)
	}
	body := string(content)

	lines := strings.Split(body, "\n")
	inGitHubBlock := false
	hasProfileAPIInGitHubBlock := false

	for _, line := range lines {
		if strings.Contains(line, "AuthMethodGitHub") {
			inGitHubBlock = true
		}
		if inGitHubBlock && strings.Contains(line, "} else {") {
			inGitHubBlock = false
			break
		}
		if inGitHubBlock && strings.Contains(line, `"/api/user/:username"`) {
			hasProfileAPIInGitHubBlock = true
			break
		}
	}

	if !hasProfileAPIInGitHubBlock {
		t.Errorf("github mode should register /api/user/:username for profile page")
	}
}

func TestProfilePage_GitHubModeReadOnlyInfo(t *testing.T) {
	content, err := os.ReadFile("../templates/profile.html")
	if err != nil {
		t.Fatalf("failed to read profile.html: %v", err)
	}
	body := string(content)

	if !strings.Contains(body, ".authMethod") {
		t.Errorf("expected profile page to use .authMethod for mode switching")
	}

	if !strings.Contains(body, "github") {
		t.Errorf("expected profile page to mention github in github mode")
	}
}

func TestProfilePage_LocalModeHasPasswordForm(t *testing.T) {
	content, err := os.ReadFile("../templates/profile.html")
	if err != nil {
		t.Fatalf("failed to read profile.html: %v", err)
	}
	body := string(content)

	if !strings.Contains(body, `id="password"`) {
		t.Errorf("expected profile page to contain password input in local mode")
	}
}

func TestBaseTemplate_GitHubModeHidesUserSettings(t *testing.T) {
	content, err := os.ReadFile("../templates/base.html")
	if err != nil {
		t.Fatalf("failed to read base.html: %v", err)
	}
	body := string(content)

	if !strings.Contains(body, ".authMethod") {
		t.Errorf("expected base.html to use .authMethod for mode switching")
	}

	if !strings.Contains(body, "users-settings") {
		t.Errorf("expected base.html to contain 'users-settings' link")
	}

	lines := strings.Split(body, "\n")
	inAdminBlock := false
	hasUserSettingsWithoutGithubCheck := false

	for _, line := range lines {
		if strings.Contains(line, "{{if .baseData.Admin}}") {
			inAdminBlock = true
		}
		if inAdminBlock && strings.Contains(line, "{{end}}") && !strings.Contains(line, "{{else}}") {
			inAdminBlock = false
		}
		if inAdminBlock && strings.Contains(line, "users-settings") && strings.Contains(line, "{{if") && strings.Contains(line, "github") {
			hasUserSettingsWithoutGithubCheck = true
			break
		}
	}

	if !hasUserSettingsWithoutGithubCheck {
		return
	}
	t.Errorf("users-settings should be hidden in github mode")
}

func TestUtil_CurrentAuthMethodType(t *testing.T) {
	if string(util.AuthMethodGitHub) != "github" {
		t.Errorf("AuthMethodGitHub should be 'github', got '%s'", util.AuthMethodGitHub)
	}

	if string(util.AuthMethodLocal) != "local" {
		t.Errorf("AuthMethodLocal should be 'local', got '%s'", util.AuthMethodLocal)
	}
}
