package geoip

import "testing"

func TestFlagEmoji(t *testing.T) {
	us := string([]rune{0x1F1FA, 0x1F1F8})
	gr := string([]rune{0x1F1EC, 0x1F1F7})
	gb := string([]rune{0x1F1EC, 0x1F1E7})

	cases := map[string]string{
		"US":  us,
		"GR":  gr,
		"gb":  gb, // lowercase is normalized
		"":    "",
		"U":   "", // too short
		"USA": "", // too long
		"1A":  "", // non-letter
	}
	for in, want := range cases {
		if got := flagEmoji(in); got != want {
			t.Errorf("flagEmoji(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLocationDisplay(t *testing.T) {
	flag := string([]rune{0x1F1EC, 0x1F1F7})
	cases := []struct {
		loc  Location
		want string
	}{
		{Location{City: "Athens", Country: "Greece", Flag: flag}, flag + " Athens, Greece"},
		{Location{Country: "Greece", Flag: flag}, flag + " Greece"},
		{Location{Flag: flag}, flag},
		{Location{City: "Athens", Country: "Greece"}, "Athens, Greece"},
		{Location{}, ""},
	}
	for _, c := range cases {
		if got := c.loc.Display(); got != c.want {
			t.Errorf("Display(%+v) = %q, want %q", c.loc, got, c.want)
		}
	}
}

func TestLookupNotLoaded(t *testing.T) {
	mu.Lock()
	reader = nil
	mu.Unlock()
	if _, err := Lookup("8.8.8.8"); err == nil {
		t.Error("expected error when database not loaded, got nil")
	}
}
