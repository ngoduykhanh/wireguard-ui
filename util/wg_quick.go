package util

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/labstack/gommon/log"
)

func ensureWgQuickAllowed(confPath string) (string, error) {
	confPath = strings.TrimSpace(confPath)
	if confPath == "" {
		return "", fmt.Errorf("missing config file path")
	}
	if !filepath.IsAbs(confPath) {
		return "", fmt.Errorf("config path must be absolute")
	}
	if !LookupEnvOrBool(AllowWgQuickCtlEnvVar, false) {
		return "", fmt.Errorf("wg-quick controls disabled (set %s=true)", AllowWgQuickCtlEnvVar)
	}
	return confPath, nil
}

// RunWgQuickDown runs `wg-quick down <config>` only when WGUI_ALLOW_WG_QUICK is enabled (security gate).
func RunWgQuickDown(confPath string) error {
	p, err := ensureWgQuickAllowed(confPath)
	if err != nil {
		return err
	}
	out, err := exec.Command("wg-quick", "down", p).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick down: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// wgQuickDownBestEffort clears a half-dead or lingering wg netdev before "up" (ignored errors).
// Avoids races where a previous failed wg-quick up left the stack inconsistent and the next
// ip -6 route (or similar) fails with "Cannot find device wg0" even though Bring-up mostly worked.
func wgQuickDownBestEffort(absConf string) {
	out, err := exec.Command("wg-quick", "down", absConf).CombinedOutput()
	if err != nil && strings.TrimSpace(string(out)) != "" {
		log.Debugf("wg-quick down (best-effort): %v: %s", err, strings.TrimSpace(string(out)))
	}
	time.Sleep(200 * time.Millisecond)
}

// RunWgQuickUp runs `wg-quick up <config>` only when WGUI_ALLOW_WG_QUICK is enabled (security gate).
func RunWgQuickUp(confPath string) error {
	p, err := ensureWgQuickAllowed(confPath)
	if err != nil {
		return err
	}
	if err := PromotePendingWgConfIfAny(p); err != nil {
		return err
	}
	wgQuickDownBestEffort(p)
	out, err := exec.Command("wg-quick", "up", p).CombinedOutput()
	if err != nil {
		log.Warnf("wg-quick up first attempt failed (%v), retrying after another down+pause", err)
		wgQuickDownBestEffort(p)
		out, err = exec.Command("wg-quick", "up", p).CombinedOutput()
	}
	if err != nil {
		return fmt.Errorf("wg-quick up: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// wgQuickSystemdUnitName returns e.g. "wg-quick@wg0", matching journalctl/systemctl `-u wg-quick@iface`.
func wgQuickSystemdUnitName(confPath string) string {
	iface := WireGuardIfaceBasename(confPath)
	if strings.TrimSpace(iface) == "" {
		iface = "wg0"
	}
	return "wg-quick@" + iface
}

func systemdShowLoadState(unit string) (string, error) {
	out, err := exec.Command("systemctl", "show", unit, "-p", "LoadState", "--value").CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func wgIfaceForConfPath(confPath string) string {
	iface := WireGuardIfaceBasename(strings.TrimSpace(confPath))
	if strings.TrimSpace(iface) == "" {
		return "wg0"
	}
	return iface
}

// WgConfPendingSuffix names the side-car file Apply uses while the tunnel is stopped (avoid path units on wg.conf).
const WgConfPendingSuffix = ".wgui-pending"

// WgConfPendingPath returns canonical + suffix.
func WgConfPendingPath(canonical string) string {
	return strings.TrimSpace(canonical) + WgConfPendingSuffix
}

// RemoveWgConfPending deletes the pending side-car if present (best-effort).
func RemoveWgConfPending(canonical string) {
	_ = os.Remove(WgConfPendingPath(canonical))
}

// PromotePendingWgConfIfAny merges <canonical>.wgui-pending over canonical before wg-quick up / systemd restart.
func PromotePendingWgConfIfAny(canonical string) error {
	canonical = strings.TrimSpace(canonical)
	if canonical == "" || !filepath.IsAbs(canonical) {
		return fmt.Errorf("invalid wg config path for promote")
	}
	pending := WgConfPendingPath(canonical)
	if _, err := os.Stat(pending); err != nil {
		return nil
	}
	b, err := os.ReadFile(pending)
	if err != nil {
		return fmt.Errorf("read pending wg.conf: %w", err)
	}
	dir := filepath.Dir(canonical)
	tmpPath := filepath.Join(dir, fmt.Sprintf(".wgui-wg-merge-%d.tmp", os.Getpid()))
	if err := os.WriteFile(tmpPath, b, 0600); err != nil {
		return fmt.Errorf("write staged wg.conf: %w", err)
	}
	if err := os.Rename(tmpPath, canonical); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("promote pending wg.conf: %w", err)
	}
	_ = os.Remove(pending)
	return nil
}

func wgShowIfaceNonEmpty(iface string) bool {
	wgBin, err := exec.LookPath("wg")
	if err != nil {
		return false
	}
	out, err := exec.Command(wgBin, "show", iface).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

func linuxWgIfaceOperUp(iface string) bool {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return false
	}
	meta := filepath.Join("/sys/class/net", iface)
	fi, err := os.Stat(meta)
	if err != nil || !fi.IsDir() {
		return false
	}
	b, err := os.ReadFile(filepath.Join(meta, "operstate"))
	if err != nil {
		return false
	}
	s := strings.TrimSpace(strings.ToLower(string(b)))
	// wg netdev is often unknown while running; iface missing after wg-quick down.
	return s == "up" || s == "unknown"
}

// WgTunnelIsRunning prefers sysfs netdev state on Linux — avoids systemd and stale wg dumps.
func WgTunnelIsRunning(confPath string) bool {
	p := strings.TrimSpace(confPath)
	if p == "" {
		return false
	}
	iface := wgIfaceForConfPath(p)
	if runtime.GOOS == "linux" {
		return linuxWgIfaceOperUp(iface)
	}
	return wgShowIfaceNonEmpty(iface)
}

// RestartWgQuick runs `wg-quick down` + `wg-quick up` unless a matching systemd unit is active (see WGUI_WG_RESTART_VIA_SYSTEMD),
// in which case `systemctl restart wg-quick@iface` is used so journalctl -u wg-quick@iface captures the event.
func RestartWgQuick(confPath string) error {
	p, err := ensureWgQuickAllowed(confPath)
	if err != nil {
		return err
	}
	if err := PromotePendingWgConfIfAny(p); err != nil {
		return err
	}

	if runtime.GOOS == "linux" && LookupEnvOrBool(RestartWGViaSystemdEnvVar, true) {
		if _, lpErr := exec.LookPath("systemctl"); lpErr == nil {
			unit := wgQuickSystemdUnitName(p)
			loadState, lsErr := systemdShowLoadState(unit)
			if lsErr == nil && loadState == "loaded" {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				out, rstErr := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput()
				if rstErr == nil {
					log.Infof("WireGuard restart: systemctl restart %s", unit)
					return nil
				}
				log.Warnf("systemctl restart %s failed (%v), falling back to wg-quick: %s", unit, rstErr, strings.TrimSpace(string(out)))
			}
		}
	}

	_ = RunWgQuickDown(p)
	return RunWgQuickUp(p)
}

