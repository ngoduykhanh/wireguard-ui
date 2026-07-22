package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAndroidPasskeySHA256FingerprintsCSV_inline(t *testing.T) {
	t.Setenv(WGUIAndroidPasskeySHA256EnvVar, " AA:01 , 02:03 ")
	got := AndroidPasskeySHA256FingerprintsCSV()
	want := "AA:01 , 02:03"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAndroidPasskeySHA256FingerprintsCSV_fromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sha.secret")
	if err := os.WriteFile(p, []byte("  DE:AD:BE:EF  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(WGUIAndroidPasskeySHA256EnvVar, p)
	got := AndroidPasskeySHA256FingerprintsCSV()
	want := "DE:AD:BE:EF"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAndroidPasskeySHA256FingerprintsCSV_missingFileUsesLiteral(t *testing.T) {
	t.Setenv(WGUIAndroidPasskeySHA256EnvVar, "/no/such/file/for-passkey-sha")
	got := AndroidPasskeySHA256FingerprintsCSV()
	if got != "/no/such/file/for-passkey-sha" {
		t.Fatalf("got %q", got)
	}
}
