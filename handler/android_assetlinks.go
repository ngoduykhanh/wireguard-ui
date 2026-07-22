package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/ngoduykhanh/wireguard-ui/util"
)

// Digital Asset Links payload for linking the Android WireGuard UI client passkeys ↔ this HTTPS host.
//
// Android Credential Manager ONLY requests https://<rpId>/.well-known/assetlinks.json at the
// host root (not under wireguard-ui BASE_PATH). If your reverse proxy routes only /wg to this
// process, GET / returns 404 and passkeys fail with "RP ID cannot be validated". Fix by:
//
//   - ProxyPass (or equivalent) from host "/.well-known/assetlinks.json" to this app's same path,
//     or mirror the JSON to a static file at that URL; or
//   - Curl the duplicate endpoint https://<host><BASE_PATH>/.well-known/assetlinks.json (see
//     main.go) and install that file under the vhost DocumentRoot /.well-known/.
//
// Ref: https://developers.google.com/digital-asset-links/v1/getting-started

type assetLinkStatement struct {
	Relation []string               `json:"relation"`
	Target   assetLinkTargetAndroid `json:"target"`
}

type assetLinkTargetAndroid struct {
	Namespace              string   `json:"namespace"`
	PackageName            string   `json:"package_name"`
	Sha256CertFingerprints []string `json:"sha256_cert_fingerprints"`
}

func AndroidDigitalAssetLinks() echo.HandlerFunc {
	return func(c echo.Context) error {
		shaRaw := strings.TrimSpace(util.AndroidPasskeySHA256FingerprintsCSV())
		if shaRaw == "" {
			return echo.NewHTTPError(http.StatusNotFound, "digital asset links not configured (set WGUI_ANDROID_PASSKEY_SHA256)")
		}
		pkg := strings.TrimSpace(util.AndroidPasskeyPackageName())
		if pkg == "" {
			pkg = "com.wireguardui.wireguard_ui_client"
		}

		fpStrings := strings.Split(shaRaw, ",")
		fingerprints := make([]string, 0, len(fpStrings))
		for _, frag := range fpStrings {
			norm, err := normalizeAndroidCertFingerprint(frag)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("invalid WGUI_ANDROID_PASSKEY_SHA256: %v", err))
			}
			fingerprints = append(fingerprints, norm)
		}

		target := assetLinkTargetAndroid{
			Namespace:              "android_app",
			PackageName:            pkg,
			Sha256CertFingerprints: fingerprints,
		}
		payload := []assetLinkStatement{
			{Relation: []string{"delegate_permission/common.get_login_creds"}, Target: target},
			{Relation: []string{"delegate_permission/common.handle_all_urls"}, Target: target},
		}

		b, err := json.Marshal(payload)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		// curl -I and some proxies use HEAD; Echo only binds GET unless we reply explicitly.
		if c.Request().Method == http.MethodHead {
			h := c.Response().Header()
			h.Set(echo.HeaderContentType, "application/json")
			h.Set(echo.HeaderContentLength, strconv.Itoa(len(b)))
			c.Response().WriteHeader(http.StatusOK)
			return nil
		}
		return c.Blob(http.StatusOK, "application/json", b)
	}
}

func normalizeAndroidCertFingerprint(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(raw, " ", "")))
	s = strings.ReplaceAll(s, ":", "")
	if len(s) != 64 {
		return "", fmt.Errorf("want 64 hex chars (SHA-256), got length %d", len(s))
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return "", fmt.Errorf("non-hex fingerprint")
		}
	}
	var b strings.Builder
	for i := 0; i < 64; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strings.ToUpper(s[i : i+2]))
	}
	return b.String(), nil
}
