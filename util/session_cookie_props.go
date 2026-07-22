package util

import (
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
)

// Session cookie flags for Flutter Web / SPA clients that talk to wireguard-ui
// across origins (e.g. localhost:xxxxx → https://vpn.example/wg).
//
// Web defaults (recommended when using Flutter -d chrome against a HTTPS server):
//
//	WGUI_SESSION_COOKIE_SAMESITE=none
//	WGUI_SESSION_COOKIE_SECURE=true   (implicitly true when samesite=none)
//
// For normal browser navigation on the same site as the UI, omit these (defaults: Lax).
func sessionCookieSameSite() http.SameSite {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WGUI_SESSION_COOKIE_SAMESITE"))) {
	case "none":
		return http.SameSiteNoneMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteLaxMode
	}
}

func sessionCookieSecure() bool {
	secure := LookupEnvOrBool("WGUI_SESSION_COOKIE_SECURE", false)
	if sessionCookieSameSite() == http.SameSiteNoneMode {
		return true // browsers require Secure with SameSite=None
	}
	return secure
}

// ApplySessionSecureFlags sets HttpOnly/SameSite/Secure on gorilla/session options.
func ApplySessionSecureFlags(o *sessions.Options) {
	if o == nil {
		return
	}
	o.HttpOnly = true
	o.SameSite = sessionCookieSameSite()
	o.Secure = sessionCookieSecure()
}

// ApplySessionHTTPFlags sets SameSite/Secure on the explicit session_token cookie.
func ApplySessionHTTPFlags(c *http.Cookie) {
	if c == nil {
		return
	}
	site := sessionCookieSameSite()
	c.HttpOnly = true
	c.Secure = sessionCookieSecure()
	switch site {
	case http.SameSiteNoneMode:
		c.SameSite = http.SameSiteNoneMode
	case http.SameSiteStrictMode:
		c.SameSite = http.SameSiteStrictMode
	default:
		c.SameSite = http.SameSiteLaxMode
	}
}
