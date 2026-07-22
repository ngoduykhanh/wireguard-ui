package util

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// HostUptimeApprox returns a readable uptime like "14d 6h 32m" or "—" if unknown.
func HostUptimeApprox() string {
	if runtime.GOOS != "linux" {
		return "—"
	}
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "—"
	}
	parts := strings.Fields(string(raw))
	if len(parts) < 1 {
		return "—"
	}
	sec, err := strconv.ParseFloat(parts[0], 64)
	if err != nil || sec <= 0 {
		return "—"
	}
	d := time.Duration(sec * float64(time.Second))
	days := int(d.Hours() / 24)
	hrs := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return strconv.Itoa(days) + "d " + strconv.Itoa(hrs) + "h " + strconv.Itoa(mins) + "m"
	}
	if hrs > 0 {
		return strconv.Itoa(hrs) + "h " + strconv.Itoa(mins) + "m"
	}
	return strconv.Itoa(mins) + "m"
}
