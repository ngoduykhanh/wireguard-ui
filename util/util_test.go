package util

import (
	"testing"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

func TestGetDBUserCRC32_IgnoresDisplayName(t *testing.T) {
	user1 := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Test User",
	}

	user2 := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Different Name",
	}

	hash1 := GetDBUserCRC32(user1)
	hash2 := GetDBUserCRC32(user2)

	if hash1 != hash2 {
		t.Errorf("CRC32 should be equal when only DisplayName differs: hash1=%d, hash2=%d", hash1, hash2)
	}
}

func TestGetDBUserCRC32_ChangesWhenAdminChanges(t *testing.T) {
	user1 := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Test User",
	}

	user2 := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        false,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Test User",
	}

	hash1 := GetDBUserCRC32(user1)
	hash2 := GetDBUserCRC32(user2)

	if hash1 == hash2 {
		t.Errorf("CRC32 should change when Admin field changes: hash1=%d, hash2=%d", hash1, hash2)
	}
}

func TestGetDBUserCRC32_ChangesWhenPasswordChanges(t *testing.T) {
	user1 := model.User{
		Username:     "testuser",
		Password:     "password1",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Test User",
	}

	user2 := model.User{
		Username:     "testuser",
		Password:     "password2",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Test User",
	}

	hash1 := GetDBUserCRC32(user1)
	hash2 := GetDBUserCRC32(user2)

	if hash1 == hash2 {
		t.Errorf("CRC32 should change when Password field changes: hash1=%d, hash2=%d", hash1, hash2)
	}
}

func TestGetDBUserCRC32_ChangesWhenAuthSourceChanges(t *testing.T) {
	user1 := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "local",
		AuthSubject:  "",
		DisplayName:  "Test User",
	}

	user2 := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "github",
		AuthSubject:  "12345",
		DisplayName:  "Test User",
	}

	hash1 := GetDBUserCRC32(user1)
	hash2 := GetDBUserCRC32(user2)

	if hash1 == hash2 {
		t.Errorf("CRC32 should change when AuthSource field changes: hash1=%d, hash2=%d", hash1, hash2)
	}
}

func TestGetDBUserCRC32_ChangesWhenAuthSubjectChanges(t *testing.T) {
	user1 := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "github",
		AuthSubject:  "12345",
		DisplayName:  "Test User",
	}

	user2 := model.User{
		Username:     "testuser",
		Password:     "password",
		PasswordHash: "hash",
		Admin:        true,
		AuthSource:   "github",
		AuthSubject:  "67890",
		DisplayName:  "Test User",
	}

	hash1 := GetDBUserCRC32(user1)
	hash2 := GetDBUserCRC32(user2)

	if hash1 == hash2 {
		t.Errorf("CRC32 should change when AuthSubject field changes: hash1=%d, hash2=%d", hash1, hash2)
	}
}

func TestGetDBUserCRC32_DistinguishesEmbeddedNulls(t *testing.T) {
	user1 := model.User{
		Username:     "user\x00name",
		Password:     "pass",
		PasswordHash: "hash",
		Admin:        false,
		AuthSource:   "github",
		AuthSubject:  "subject",
	}

	user2 := model.User{
		Username:     "user",
		Password:     "\x00namepass",
		PasswordHash: "hash",
		Admin:        false,
		AuthSource:   "github",
		AuthSubject:  "subject",
	}

	if GetDBUserCRC32(user1) == GetDBUserCRC32(user2) {
		t.Fatal("CRC32 should distinguish values even when fields contain embedded null bytes")
	}
}
