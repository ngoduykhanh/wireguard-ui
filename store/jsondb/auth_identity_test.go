package jsondb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/sdomino/scribble"
)

func TestGetUserByAuthIdentity_FindsGitHubUser(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	githubUser := model.User{
		Username:     "github-user",
		Password:     "",
		PasswordHash: "",
		Admin:        false,
		AuthSource:   "github",
		AuthSubject:  "123456",
		DisplayName:  "GitHub User",
	}

	if err := db.SaveUser(githubUser); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	found, err := db.GetUserByAuthIdentity("github", "123456")
	if err != nil {
		t.Fatalf("GetUserByAuthIdentity failed: %v", err)
	}

	if found.Username != "github-user" {
		t.Errorf("expected username 'github-user', got %q", found.Username)
	}
	if found.AuthSource != "github" {
		t.Errorf("expected auth_source 'github', got %q", found.AuthSource)
	}
	if found.AuthSubject != "123456" {
		t.Errorf("expected auth_subject '123456', got %q", found.AuthSubject)
	}
}

func TestGetUserByAuthIdentity_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	_, err = db.GetUserByAuthIdentity("github", "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent auth identity")
	}
}

func TestGetUserByAuthIdentity_LocalUserNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	localUser := model.User{
		Username:     "local-user",
		Password:     "secret",
		PasswordHash: "hash",
		Admin:        false,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Local User",
	}

	if err := db.SaveUser(localUser); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	_, err = db.GetUserByAuthIdentity("local", "")
	if err == nil {
		t.Error("expected error for local user queried by empty auth identity")
	}
}

func TestReplaceUser_RenameKeepsOnlyNewRecord(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	oldUser := model.User{
		Username:     "oldname",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Old Name",
	}

	if err := db.SaveUser(oldUser); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	newUser := model.User{
		Username:     "newname",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "New Name",
	}

	if err := db.ReplaceUser("oldname", newUser); err != nil {
		t.Fatalf("ReplaceUser failed: %v", err)
	}

	_, err = db.GetUserByName("oldname")
	if err == nil {
		t.Error("old username should not exist after rename")
	}

	_, err = db.GetUserByName("newname")
	if err != nil {
		t.Errorf("new username should exist after rename: %v", err)
	}

	users, err := db.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers failed: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected exactly 1 user after rename, got %d", len(users))
	}
}

func TestReplaceUser_SameNameUpdatesRecord(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	originalUser := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Original",
	}

	if err := db.SaveUser(originalUser); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	updatedUser := model.User{
		Username:     "testuser",
		Password:     "newpassword",
		PasswordHash: "newhash",
		Admin:        false,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Updated",
	}

	if err := db.ReplaceUser("testuser", updatedUser); err != nil {
		t.Fatalf("ReplaceUser failed: %v", err)
	}

	found, err := db.GetUserByName("testuser")
	if err != nil {
		t.Fatalf("GetUserByName failed: %v", err)
	}

	if found.Admin != false {
		t.Errorf("expected admin=false, got %v", found.Admin)
	}
	if found.DisplayName != "Updated" {
		t.Errorf("expected display_name='Updated', got %q", found.DisplayName)
	}

	users, err := db.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers failed: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected exactly 1 user after update, got %d", len(users))
	}
}

func TestReplaceUser_MigratesLegacyLocalUser(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	legacyUser := model.User{
		Username:     "legacyuser",
		Password:     "oldpassword",
		PasswordHash: "oldhash",
		Admin:        false,
		AuthSource:   "",
		AuthSubject:  "",
		DisplayName:  "",
	}

	if err := db.SaveUser(legacyUser); err != nil {
		t.Fatalf("failed to save legacy user: %v", err)
	}

	migratedUser := model.User{
		Username:     "legacyuser",
		Password:     "",
		PasswordHash: "",
		Admin:        false,
		AuthSource:   "github",
		AuthSubject:  "987654",
		DisplayName:  "Migrated User",
	}

	if err := db.ReplaceUser("legacyuser", migratedUser); err != nil {
		t.Fatalf("ReplaceUser failed: %v", err)
	}

	found, err := db.GetUserByAuthIdentity("github", "987654")
	if err != nil {
		t.Fatalf("GetUserByAuthIdentity failed: %v", err)
	}

	if found.Username != "legacyuser" {
		t.Errorf("expected username 'legacyuser', got %q", found.Username)
	}
	if found.AuthSource != "github" {
		t.Errorf("expected auth_source 'github', got %q", found.AuthSource)
	}
	if found.AuthSubject != "987654" {
		t.Errorf("expected auth_subject '987654', got %q", found.AuthSubject)
	}
	if found.Password != "" || found.PasswordHash != "" {
		t.Errorf("expected empty password fields for migrated user, got password=%q, password_hash=%q", found.Password, found.PasswordHash)
	}
}

func TestReplaceUser_WriteNewFails_KeepsOldRecord(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	existingUser := model.User{
		Username:     "existing",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Existing User",
	}

	if err := db.SaveUser(existingUser); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	userDir := filepath.Join(tmpDir, "users")
	os.Chmod(userDir, 0000)

	newUser := model.User{
		Username:     "newuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        false,
		AuthSource:   "github",
		AuthSubject:  "123456",
		DisplayName:  "New User",
	}

	err = db.ReplaceUser("existing", newUser)

	os.Chmod(userDir, 0700)

	if err == nil {
		t.Error("expected error when writing new record fails")
	}

	_, err = db.GetUserByName("existing")
	if err != nil {
		t.Errorf("old record should still exist after failed replace: %v", err)
	}

	_, err = db.GetUserByName("newuser")
	if err == nil {
		t.Error("new record should not exist after failed replace")
	}
}

func TestReplaceUser_DeleteOldFails_AttemptsRollbackBeforeManualCleanupError(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	oldUser := model.User{
		Username:     "olduser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Old User",
	}

	if err := db.SaveUser(oldUser); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	newUser := model.User{
		Username:     "newuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "New User",
	}

	origDeleteUserFile := deleteUserFile
	deleteUserFile = func(conn *scribble.Driver, username string) error {
		if username == "olduser" {
			return fmt.Errorf("simulated delete failure for olduser")
		}
		if username == "newuser" {
			return fmt.Errorf("simulated rollback failure for newuser")
		}
		return origDeleteUserFile(conn, username)
	}
	defer func() { deleteUserFile = origDeleteUserFile }()

	err = db.ReplaceUser("olduser", newUser)

	if err == nil {
		t.Fatal("expected error when delete old fails and rollback also fails")
	}

	if !strings.Contains(err.Error(), "manual cleanup required") {
		t.Errorf("error should contain 'manual cleanup required', got: %v", err)
	}

	if !strings.Contains(err.Error(), "rollback failed") {
		t.Errorf("error should contain 'rollback failed', got: %v", err)
	}

	_, err = db.GetUserByName("olduser")
	if err != nil {
		t.Errorf("old record should still exist: %v", err)
	}

	_, err = db.GetUserByName("newuser")
	if err != nil {
		t.Errorf("new record should still exist after failed rollback: %v", err)
	}
}
