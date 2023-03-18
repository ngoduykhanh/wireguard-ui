package model

// User model
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// PasswordHash takes precedence over Password.
	PasswordHash string `json:"password_hash"`
	Admin        bool   `json:"admin"`
}
