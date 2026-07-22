package model

import "github.com/go-webauthn/webauthn/webauthn"

// User model
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// PasswordHash takes precedence over Password.
	PasswordHash string `json:"password_hash"`
	Admin        bool   `json:"admin"`
	// Disabled accounts cannot log in; existing sessions are invalidated via AuthEpoch bumps.
	Disabled bool `json:"disabled,omitempty"`
	// AuthEpoch is incremented by admins to revoke all sessions for this user without changing the password.
	AuthEpoch int64 `json:"auth_epoch,omitempty"`
	// DisplayName / Email are optional UI fields (admin users page).
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	// PasskeyLabels maps credential ID (base64 RawURLEncoding) to a user-visible name.
	PasskeyLabels map[string]string `json:"passkey_labels,omitempty"`
	Passkeys      []webauthn.Credential `json:"passkeys,omitempty"`
}
