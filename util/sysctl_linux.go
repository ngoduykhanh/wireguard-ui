//go:build linux

package util

import (
	"fmt"
	"os/exec"
	"strings"
)

// ApplyIPv4ForwardSysctl sets net.ipv4.ip_forward via sysctl when WGUI_ALLOW_SYSCTL_IP_FORWARD is true.
func ApplyIPv4ForwardSysctl(enabled bool) error {
	if !LookupEnvOrBool(AllowSysctlIPForwardEnvVar, false) {
		return nil
	}
	val := "0"
	if enabled {
		val = "1"
	}
	out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward="+val).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
