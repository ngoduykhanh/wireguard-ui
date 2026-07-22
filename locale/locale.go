package locale

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"strings"
	"sync"
)

//go:embed es.json en.json
var embedded embed.FS

var (
	mu   sync.RWMutex
	es   map[string]string
	en   map[string]string
	once sync.Once
)

func load() {
	once.Do(func() {
		es = mustLoadJSON("es.json")
		en = mustLoadJSON("en.json")
	})
}

func mustLoadJSON(name string) map[string]string {
	b, err := embedded.ReadFile(name)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]string{}
	}
	return out
}

// Normalize converts stored UI language to "en" or "es".
func Normalize(lang string) string {
	if strings.EqualFold(strings.TrimSpace(lang), "en") {
		return "en"
	}
	return "es"
}

// T returns translated string for lang (falls back ES → EN → key).
func T(lang, key string) string {
	load()
	if key == "" {
		return ""
	}
	lang = Normalize(lang)

	mu.RLock()
	defer mu.RUnlock()

	pick := func(m map[string]string) (string, bool) {
		if m == nil {
			return "", false
		}
		v, ok := m[key]
		return v, ok && v != ""
	}

	if lang == "en" {
		if v, ok := pick(en); ok {
			return v
		}
		if v, ok := pick(es); ok {
			return v
		}
		return key
	}
	if v, ok := pick(es); ok {
		return v
	}
	if v, ok := pick(en); ok {
		return v
	}
	return key
}

// MsgMap returns merged messages for client-side (ES base + EN overrides).
func MsgMap(lang string) map[string]string {
	load()
	lang = Normalize(lang)
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]string, len(es)+len(en))
	for k, v := range es {
		out[k] = v
	}
	if lang == "en" && en != nil {
		for k, v := range en {
			if strings.TrimSpace(v) != "" {
				out[k] = v
			}
		}
	}
	return out
}

// JSONForHTML returns Safe JSON assignment for `<script>var x = {{.}};</script>`.
func JSONForHTML(lang string) template.JS {
	m := MsgMap(lang)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(m); err != nil {
		return template.JS("{}")
	}
	// Trim newline from Encoder
	s := strings.TrimSpace(buf.String())
	return template.JS(s)
}
