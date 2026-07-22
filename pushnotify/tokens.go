package pushnotify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/labstack/gommon/log"
)

const tokensFile = "push_tokens.json"

type TokenRecord struct {
	Username string `json:"username"`
	Token    string `json:"token"`
	Platform string `json:"platform"`
	Updated  int64  `json:"updated"`
}

type tokenFile struct {
	Tokens []TokenRecord `json:"tokens"`
}

var tokenMu sync.Mutex

func tokensPath(dbPath string) string {
	return filepath.Join(dbPath, tokensFile)
}

func readTokensFile(dbPath string) ([]TokenRecord, error) {
	p := tokensPath(dbPath)
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var tf tokenFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return nil, err
	}
	return tf.Tokens, nil
}

func writeTokensFile(dbPath string, list []TokenRecord) error {
	p := tokensPath(dbPath)
	tf := tokenFile{Tokens: list}
	b, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0600)
}

func loadTokens(dbPath string) ([]TokenRecord, error) {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	return readTokensFile(dbPath)
}

// RegisterOrUpdate adds/replaces a token for this user (one row per device token).
func RegisterOrUpdate(dbPath, username, token, platform string) error {
	if dbPath == "" || username == "" || token == "" {
		return nil
	}
	tokenMu.Lock()
	defer tokenMu.Unlock()
	list, err := readTokensFile(dbPath)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	platform = strings.TrimSpace(platform)
	out := make([]TokenRecord, 0, len(list)+1)
	replaced := false
	for _, r := range list {
		if r.Token == token {
			r.Username = username
			r.Platform = platform
			r.Updated = now
			out = append(out, r)
			replaced = true
			continue
		}
		out = append(out, r)
	}
	if !replaced {
		out = append(out, TokenRecord{
			Username: username,
			Token:    token,
			Platform: platform,
			Updated:  now,
		})
	}
	if err := writeTokensFile(dbPath, out); err != nil {
		return err
	}
	log.Infof("FCM token registered for user %s", username)
	return nil
}

// Unregister removes a token.
func Unregister(dbPath, token string) error {
	if dbPath == "" || token == "" {
		return nil
	}
	tokenMu.Lock()
	defer tokenMu.Unlock()
	list, err := readTokensFile(dbPath)
	if err != nil {
		return err
	}
	out := make([]TokenRecord, 0, len(list))
	for _, r := range list {
		if r.Token != token {
			out = append(out, r)
		}
	}
	return writeTokensFile(dbPath, out)
}
