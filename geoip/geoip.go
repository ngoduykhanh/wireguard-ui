// Package geoip provides GeoLite2 (MaxMind) city geolocation with a locally
// stored database that can be installed/updated on demand or automatically.
package geoip

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// download endpoint for the GeoLite2-City edition (tar.gz archive)
const downloadURLTemplate = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz"

// guard against decompression bombs; the GeoLite2-City db is ~70MB
const maxDBSize = 1 << 30 // 1 GiB

var (
	mu     sync.RWMutex
	reader *geoip2.Reader
	dbPath = "./db/GeoLite2-City.mmdb"
)

// Location holds the resolved geolocation of an IP address.
type Location struct {
	City       string
	Country    string
	CountryISO string
	Flag       string
}

// Display renders the location as "🇬🇷 Athens, Greece", omitting empty parts.
func (l Location) Display() string {
	var parts []string
	if l.City != "" {
		parts = append(parts, l.City)
	}
	if l.Country != "" {
		parts = append(parts, l.Country)
	}
	text := strings.Join(parts, ", ")
	switch {
	case l.Flag != "" && text != "":
		return l.Flag + " " + text
	case l.Flag != "":
		return l.Flag
	default:
		return text
	}
}

// SetDBPath configures where the GeoLite2 database is stored/read.
func SetDBPath(p string) {
	if strings.TrimSpace(p) != "" {
		dbPath = p
	}
}

// DBPath returns the configured database path.
func DBPath() string {
	return dbPath
}

// Load opens the local database (if present) into the reader.
func Load() error {
	if _, err := os.Stat(dbPath); err != nil {
		return err
	}
	r, err := geoip2.Open(dbPath)
	if err != nil {
		return err
	}
	mu.Lock()
	old := reader
	reader = r
	mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// Available reports whether a database is loaded and ready for lookups.
func Available() bool {
	mu.RLock()
	defer mu.RUnlock()
	return reader != nil
}

// LastUpdated returns the database file's modification time.
func LastUpdated() (time.Time, bool) {
	fi, err := os.Stat(dbPath)
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

// NeedsUpdate reports whether the database is missing or older than maxAge.
func NeedsUpdate(maxAge time.Duration) bool {
	t, ok := LastUpdated()
	if !ok {
		return true
	}
	return time.Since(t) > maxAge
}

// Lookup geolocates an IP address (host only, without port).
func Lookup(ipStr string) (Location, error) {
	mu.RLock()
	r := reader
	mu.RUnlock()
	if r == nil {
		return Location{}, errors.New("geoip database not loaded")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Location{}, fmt.Errorf("invalid ip address: %q", ipStr)
	}
	record, err := r.City(ip)
	if err != nil {
		return Location{}, err
	}
	loc := Location{
		City:       record.City.Names["en"],
		Country:    record.Country.Names["en"],
		CountryISO: record.Country.IsoCode,
	}
	loc.Flag = flagEmoji(loc.CountryISO)
	return loc, nil
}

// flagEmoji converts a two-letter ISO country code into its flag emoji using
// Unicode regional indicator symbols.
func flagEmoji(iso string) string {
	if len(iso) != 2 {
		return ""
	}
	iso = strings.ToUpper(iso)
	runes := make([]rune, 0, 2)
	for _, c := range iso {
		if c < 'A' || c > 'Z' {
			return ""
		}
		runes = append(runes, rune(0x1F1E6+(c-'A')))
	}
	return string(runes)
}

// Update downloads the latest GeoLite2-City database with the given MaxMind
// license key, atomically replaces the local file, and reloads the reader.
func Update(licenseKey string) error {
	licenseKey = strings.TrimSpace(licenseKey)
	if licenseKey == "" {
		return errors.New("MaxMind license key is not set")
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(fmt.Sprintf(downloadURLTemplate, licenseKey))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with HTTP %d (check your MaxMind license key)", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return err
	}

	tmpPath := dbPath + ".tmp"
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		out, err := os.Create(tmpPath)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, maxDBSize)); err != nil {
			out.Close()
			os.Remove(tmpPath)
			return err
		}
		out.Close()
		found = true
		break
	}
	if !found {
		return errors.New("no .mmdb file found in the downloaded archive")
	}

	_ = os.Chmod(tmpPath, 0600)
	if err := os.Rename(tmpPath, dbPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return Load()
}
