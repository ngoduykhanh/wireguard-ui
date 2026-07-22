//go:build !linux

package util

// ApplyIPv4ForwardSysctl sets net.ipv4.ip_forward via sysctl when WGUI_ALLOW_SYSCTL_IP_FORWARD is true (Linux only).
func ApplyIPv4ForwardSysctl(enabled bool) error {
	return nil
}
