package util

import (
	"path/filepath"
	"strings"
)

// WireGuardIfaceBasename returns the wg interface id (e.g. wg0) from a config path (/etc/wireguard/wg0.conf → wg0).
func WireGuardIfaceBasename(confPath string) string {
	b := filepath.Base(strings.TrimSpace(confPath))
	b = strings.TrimSuffix(b, ".conf")
	if b == "." || b == "/" || b == "" {
		return "wg0"
	}
	return b
}
