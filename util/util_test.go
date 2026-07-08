package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

func TestParseConfigFileMode(t *testing.T) {
	cases := []struct {
		in      string
		want    os.FileMode
		wantErr bool
	}{
		{"", 0600, false},
		{"   ", 0600, false},
		{"0600", 0600, false},
		{"600", 0600, false},
		{"0640", 0640, false},
		{"0644", 0644, false},
		{"0777", 0777, false},
		{"nope", 0, true},
		{"0x600", 0, true},
		{"999", 0, true}, // 9 is not a valid octal digit
	}
	for _, c := range cases {
		got, err := ParseConfigFileMode(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseConfigFileMode(%q) expected error, got mode %o", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseConfigFileMode(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseConfigFileMode(%q) = %o, want %o", c.in, got, c.want)
		}
	}
}

func testServer() model.Server {
	return model.Server{
		KeyPair:   &model.ServerKeypair{PrivateKey: "priv", PublicKey: "pub"},
		Interface: &model.ServerInterface{Addresses: []string{"10.0.0.1/24"}, ListenPort: 51820},
	}
}

// minimal template that exercises the fields WriteWireGuardServerConfig injects
const testTmpl = "[Interface]\nListenPort = {{ .serverConfig.Interface.ListenPort }}\nPrivateKey = {{ .serverConfig.KeyPair.PrivateKey }}\n"

func TestWriteWireGuardServerConfigMode(t *testing.T) {
	tmplDir := fstest.MapFS{"wg.conf": &fstest.MapFile{Data: []byte(testTmpl)}}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "wg0.conf")

	// default (empty) mode must produce a 0600 file
	settings := model.GlobalSetting{ConfigFilePath: cfgPath}
	if err := WriteWireGuardServerConfig(tmplDir, testServer(), nil, nil, settings); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	fi, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("default mode = %o, want 0600", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(data), "ListenPort = 51820") {
		t.Errorf("rendered config missing expected content: %q", string(data))
	}

	// custom mode must be honored, even when overwriting an existing file
	settings.ConfigFileMode = "0640"
	if err := WriteWireGuardServerConfig(tmplDir, testServer(), nil, nil, settings); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	fi, _ = os.Stat(cfgPath)
	if fi.Mode().Perm() != 0640 {
		t.Errorf("custom mode = %o, want 0640", fi.Mode().Perm())
	}
}
