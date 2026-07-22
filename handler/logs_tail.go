package handler

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ngoduykhanh/wireguard-ui/util"
)

// LogsTailEnvVarName is the env var for an optional log file shown on the Logs page.
const LogsTailEnvVarName = "WGUI_LOG_TAIL_PATH"

// SystemLogSection is one rendered block in Logs page.
type SystemLogSection struct {
	Title string
	Cmd   string
	Lines []string
}

func tailLines(lines []string, maxLines int) []string {
	if maxLines <= 0 || len(lines) <= maxLines {
		return lines
	}
	return lines[len(lines)-maxLines:]
}

func runCommandTail(maxLines int, name string, args ...string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return []string{fmt.Sprintf("No disponible: %v", err)}
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Split(bufio.ScanLines)
	var lines []string
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 && err != nil {
		lines = []string{fmt.Sprintf("No disponible: %v", err)}
	}
	return tailLines(lines, maxLines)
}

// ReadSystemLogSections builds practical sections for wg and app logs.
func ReadSystemLogSections(iface string) []SystemLogSection {
	if strings.TrimSpace(iface) == "" {
		iface = "wg0"
	}
	wgUnit := "wg-quick@" + iface
	return []SystemLogSection{
		{
			Title: "systemctl status " + wgUnit,
			Cmd:   "systemctl status " + wgUnit + " --no-pager",
			Lines: runCommandTail(140, "systemctl", "status", wgUnit, "--no-pager"),
		},
		{
			Title: "journalctl " + wgUnit,
			Cmd:   "journalctl -u " + wgUnit + " -n 180 --no-pager --output=short-iso",
			Lines: runCommandTail(180, "journalctl", "-u", wgUnit, "-n", "180", "--no-pager", "--output=short-iso"),
		},
		{
			Title: "journalctl wireguard-ui",
			Cmd:   "journalctl -u wireguard-ui -n 180 --no-pager --output=short-iso",
			Lines: runCommandTail(180, "journalctl", "-u", "wireguard-ui", "-n", "180", "--no-pager", "--output=short-iso"),
		},
	}
}

// ReadLogTailLines reads up to maxLines lines from the end of a file path from LogsTailEnvVarName.
// Lines are trimmed; empty slice if file missing/unreadable or path unset.
func ReadLogTailLines(maxLines int) []string {
	p := util.LookupEnvOrString(LogsTailEnvVarName, "")
	if p == "" || maxLines <= 0 {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 {
		return nil
	}
	// Prefer last chunk for large logs
	maxBytes := 256 * 1024
	start := 0
	if len(b) > maxBytes {
		start = len(b) - maxBytes
		// Align to newline
		for start < len(b) && b[start] != '\n' {
			start++
		}
		if start >= len(b) {
			start = 0
		}
	}
	s := bufio.NewScanner(bytes.NewReader(b[start:]))
	s.Split(bufio.ScanLines)
	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if len(lines) <= maxLines {
		return lines
	}
	return lines[len(lines)-maxLines:]
}
