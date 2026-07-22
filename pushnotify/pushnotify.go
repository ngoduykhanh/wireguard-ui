// Package pushnotify sends Firebase Cloud Messaging (FCM) notifications from wireguard-ui.
// Configure with FCM_CREDENTIALS_FILE pointing to a Firebase service account JSON (same as GOOGLE_APPLICATION_CREDENTIALS).
package pushnotify

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"github.com/labstack/gommon/log"
	"google.golang.org/api/option"

)

var (
	mu           sync.RWMutex
	app          *firebase.App
	msgClient    *messaging.Client
	rate         *rateLimiter
	credPath     string
	dbPathGetter func() string
)

const maxPerTokenPerMinute = 3

// HeaderXWGUIFCMToken is sent by the mobile app on peer-mutation requests so Broadcast skips push to that FCM registration (same-device actions).
const HeaderXWGUIFCMToken = "X-WGUI-FCM-Token"

// Matches Flutter/Android client notification channel — see kWguAlertsChannelId.
const androidNotificationChannelID = "wgui_alerts"

// FCM/Android requires #RRGGBB without alpha — same hue as Flutter AppColors.accent (0xFF4FC3F7).
const androidNotificationAccentColor = "#4FC3F7"

type gcpServiceAccountFile struct {
	ProjectID string `json:"project_id"`
}

func resolveFirebaseProjectID(credPath string) string {
	if p := strings.TrimSpace(os.Getenv("FIREBASE_PROJECT_ID")); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_PROJECT")); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("GCLOUD_PROJECT")); p != "" {
		return p
	}
	b, err := os.ReadFile(credPath)
	if err != nil {
		return ""
	}
	var f gcpServiceAccountFile
	if err := json.Unmarshal(b, &f); err != nil {
		return ""
	}
	return strings.TrimSpace(f.ProjectID)
}

// Init loads Firebase credentials (optional). If path is empty or file missing, push is disabled.
func Init(credentialsFile string, getDBPath func() string) {
	mu.Lock()
	defer mu.Unlock()
	credPath = strings.TrimSpace(credentialsFile)
	dbPathGetter = getDBPath
	rate = newRateLimiter(maxPerTokenPerMinute)
	app = nil
	msgClient = nil
	if credPath == "" {
		log.Infof("FCM disabled (set %s to a Firebase service account JSON)", fcmCredentialsEnv())
		return
	}
	if _, err := os.Stat(credPath); err != nil {
		log.Warnf("FCM credentials file not readable (%s): %v — push disabled", credPath, err)
		credPath = ""
		return
	}
	ctx := context.Background()
	projectID := resolveFirebaseProjectID(credPath)
	if projectID == "" {
		log.Errorf("FCM: missing project_id (add \"project_id\" to the service account JSON, or set FIREBASE_PROJECT_ID) — push disabled")
		credPath = ""
		return
	}
	conf := &firebase.Config{ProjectID: projectID}
	a, err := firebase.NewApp(ctx, conf, option.WithCredentialsFile(credPath))
	if err != nil {
		log.Errorf("FCM firebase.NewApp: %v — push disabled", err)
		credPath = ""
		return
	}
	mc, err := a.Messaging(ctx)
	if err != nil {
		log.Errorf("FCM Messaging: %v — push disabled", err)
		credPath = ""
		return
	}
	app = a
	msgClient = mc
	log.Infof("FCM enabled (credentials: %s)", credPath)
}

func fcmCredentialsEnv() string {
	return "FCM_CREDENTIALS_FILE"
}

func enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return msgClient != nil && dbPathGetter != nil
}

// Broadcast sends a notification to all registered device tokens (respects per-token rate limit).
// If omitDeviceToken is non-empty, that exact token is skipped (for actions initiated from the device that owns the token).
func Broadcast(title, body string, omitDeviceToken ...string) {
	if !enabled() {
		return
	}
	var omit string
	if len(omitDeviceToken) > 0 {
		omit = strings.TrimSpace(omitDeviceToken[0])
	}
	mu.RLock()
	mc := msgClient
	mu.RUnlock()
	if mc == nil {
		return
	}
	path := dbPathGetter()
	if path == "" {
		return
	}
	tokens, err := loadTokens(path)
	if err != nil || len(tokens) == 0 {
		return
	}
	ctx := context.Background()
	for _, rec := range tokens {
		if rec.Token == "" {
			continue
		}
		if omit != "" && rec.Token == omit {
			continue
		}
		if !rate.allow(rec.Token) {
			log.Infof("FCM rate limit skip token …%s", trimTok(rec.Token))
			continue
		}
		_, sendErr := mc.Send(ctx, &messaging.Message{
			Notification: &messaging.Notification{
				Title: title,
				Body:  body,
			},
			Token: rec.Token,
			Android: &messaging.AndroidConfig{
				Priority: "high",
				Notification: &messaging.AndroidNotification{
					Color:     androidNotificationAccentColor,
					ChannelID: androidNotificationChannelID,
				},
			},
		})
		if sendErr != nil {
			if messaging.IsRegistrationTokenNotRegistered(sendErr) || messaging.IsInvalidArgument(sendErr) {
				_ = Unregister(path, rec.Token)
			} else {
				log.Warnf("FCM send: %v", sendErr)
			}
		}
	}
}

func trimTok(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[len(t)-8:]
}

// PeerCreated notifies about a new peer (omitSameDeviceFCM skips that registration).
func PeerCreated(name string, omitSameDeviceFCM string) {
	n := strings.TrimSpace(name)
	if n == "" {
		n = "(sin nombre)"
	}
	Broadcast("WireGuard UI · Peer", "Nuevo peer: "+n, omitSameDeviceFCM)
}

// PeerRemoved notifies after deletion (omitSameDeviceFCM skips that registration).
func PeerRemoved(name string, omitSameDeviceFCM string) {
	n := strings.TrimSpace(name)
	if n == "" {
		n = "peer"
	}
	Broadcast("WireGuard UI · Peer", "Peer eliminado: "+n, omitSameDeviceFCM)
}

// PeerEnableChanged notifies enable/disable (omitSameDeviceFCM skips that registration).
func PeerEnableChanged(name string, en bool, omitSameDeviceFCM string) {
	n := strings.TrimSpace(name)
	if n == "" {
		n = "peer"
	}
	msg := "deshabilitado"
	if en {
		msg = "habilitado"
	}
	Broadcast("WireGuard UI · Peer", n+": "+msg, omitSameDeviceFCM)
}

var (
	lastTunnelMu    sync.Mutex
	lastTunnelWasUp *bool
)

// TunnelRunningTransition notifies when tunnel goes up→down or down→up (first poll establishes baseline without notify).
func TunnelRunningTransition(running bool) {
	lastTunnelMu.Lock()
	defer lastTunnelMu.Unlock()
	if lastTunnelWasUp == nil {
		b := running
		lastTunnelWasUp = &b
		return
	}
	if *lastTunnelWasUp == running {
		return
	}
	*lastTunnelWasUp = running
	if running {
		Broadcast("WireGuard UI · Tunnel", "The WireGuard interface is up")
	} else {
		Broadcast("WireGuard UI · Tunnel", "The WireGuard interface is down")
	}
}

type rateLimiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	hits     map[string][]time.Time
}

func newRateLimiter(max int) *rateLimiter {
	return &rateLimiter{
		max:    max,
		window: time.Minute,
		hits:   map[string][]time.Time{},
	}
}

func (r *rateLimiter) allow(token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-r.window)
	var kept []time.Time
	for _, t := range r.hits[token] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.max {
		return false
	}
	kept = append(kept, now)
	r.hits[token] = kept
	return true
}
