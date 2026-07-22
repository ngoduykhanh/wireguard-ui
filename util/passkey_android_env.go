package util

import (
	"os"
	"strings"
)

const (
	WGUIAndroidPasskeyPackageEnvVar = "WGUI_ANDROID_PASSKEY_PACKAGE"
	WGUIAndroidPasskeySHA256EnvVar  = "WGUI_ANDROID_PASSKEY_SHA256"
)

// AndroidPasskeyPackageName is the Android applicationId for WireGuard UI client (Digital Asset Links).
func AndroidPasskeyPackageName() string {
	return strings.TrimSpace(LookupEnvOrString(WGUIAndroidPasskeyPackageEnvVar, ""))
}

// AndroidPasskeySHA256FingerprintsCSV is one or more comma-separated SHA-256 cert fingerprints for that app signing key.
//
// The environment value may be either:
//   - the fingerprints inline (hex, optional colons, comma-separated), or
//   - an absolute path to a regular file whose contents are that same string (after trim). This
//     matches common /etc/default layouts where secrets live root-owned on disk.
func AndroidPasskeySHA256FingerprintsCSV() string {
	s := strings.TrimSpace(LookupEnvOrString(WGUIAndroidPasskeySHA256EnvVar, ""))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "/") {
		if fi, err := os.Stat(s); err == nil && fi.Mode().IsRegular() {
			if b, err := os.ReadFile(s); err == nil {
				return strings.TrimSpace(string(b))
			}
		}
	}
	return s
}
