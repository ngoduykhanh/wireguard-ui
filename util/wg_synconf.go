package util

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/labstack/gommon/log"
)

// ShouldApplySyncconfAfterWrite returns whether “Apply config” should run wg-quick strip | wg syncconf after writing wg.conf.
// This is enabled only when WGUI_WG_SYNCCONF_AFTER_APPLY is explicitly set to true.
func ShouldApplySyncconfAfterWrite() bool {
	v, found := os.LookupEnv(SyncConfAfterApplyEnvVar)
	if !found {
		return false
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		log.Warnf("[%s]: %q is not a bool, disabling syncconf", SyncConfAfterApplyEnvVar, v)
		return false
	}
	return b
}

// runWgSyncConfFromSavedFile runs `wg-quick strip <conf>` then `wg syncconf <iface> <tmp-file>`.
func runWgSyncConfFromSavedFile(confPath string) error {
	confPath = strings.TrimSpace(confPath)
	if confPath == "" {
		return fmt.Errorf("missing config file path")
	}
	if !filepath.IsAbs(confPath) {
		return fmt.Errorf("config path must be absolute")
	}

	iface := WireGuardIfaceBasename(confPath)
	stripCmd := exec.Command("wg-quick", "strip", confPath)
	stripOut, err := stripCmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("wg-quick strip: %w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("wg-quick strip: %w", err)
	}

	tmpf, err := os.CreateTemp("", "wgui-syncconf-*.conf")
	if err != nil {
		return fmt.Errorf("create temp syncconf file: %w", err)
	}
	tmpPath := tmpf.Name()
	_ = tmpf.Close()
	defer os.Remove(tmpPath)

	if err := os.WriteFile(tmpPath, stripOut, 0600); err != nil {
		return fmt.Errorf("write temp syncconf file: %w", err)
	}

	syncCmd := exec.Command("wg", "syncconf", iface, tmpPath)
	out, err := syncCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg syncconf %s: %w: %s", iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// WgSyncConfFromSavedFile runs syncconf only when WGUI_WG_SYNCCONF_AFTER_APPLY is true.
// Linux only; no-op elsewhere.
func WgSyncConfFromSavedFile(confPath string) error {
	if !ShouldApplySyncconfAfterWrite() {
		return nil
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	return runWgSyncConfFromSavedFile(confPath)
}

// WgForceSyncConfFromSavedFile pushes the saved config into the kernel (strip + wg syncconf).
// Does not consult WGUI_WG_SYNCCONF_AFTER_APPLY — used after Apply requested wg-quick restart
// but restart is disabled or failed, so peers still converge without requiring that env flag.
func WgForceSyncConfFromSavedFile(confPath string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	return runWgSyncConfFromSavedFile(confPath)
}
