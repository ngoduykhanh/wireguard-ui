package util

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(plaintext string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(plaintext), 14)
	if err != nil {
		return "", fmt.Errorf("cannot hash password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func VerifyHash(base64Hash string, plaintext string) (bool, error) {
	hash, err := base64.StdEncoding.DecodeString(base64Hash)
	if err != nil {
		return false, fmt.Errorf("cannot decode base64 hash: %w", err)
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(plaintext))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot verify password: %w", err)
	}
	return true, nil
}
