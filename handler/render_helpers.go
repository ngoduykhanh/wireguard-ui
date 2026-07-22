package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ngoduykhanh/wireguard-ui/locale"
	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
	"github.com/ngoduykhanh/wireguard-ui/util"
)

// renderShell renders a shell template with common nav extras (e.g. apply-config badge).
func renderShell(c echo.Context, db store.IStore, name string, m map[string]interface{}) error {
	if m == nil {
		m = make(map[string]interface{})
	}
	if db != nil {
		if _, ok := m["globalSettings"]; !ok {
			if gs, err := db.GetGlobalSettings(); err == nil {
				m["globalSettings"] = gs
			}
		}
	}
	m["dashboardNavBadge"] = navBadgeFor(db)
	m["syncconfAfterApplyEnabled"] = util.ShouldApplySyncconfAfterWrite()
	injectUILang(db, m)
	return c.Render(http.StatusOK, name, m)
}

func renderShellErr(c echo.Context, db store.IStore, code int, name string, m map[string]interface{}) error {
	if m == nil {
		m = make(map[string]interface{})
	}
	if db != nil {
		if _, ok := m["globalSettings"]; !ok {
			if gs, err := db.GetGlobalSettings(); err == nil {
				m["globalSettings"] = gs
			}
		}
	}
	m["dashboardNavBadge"] = navBadgeFor(db)
	m["syncconfAfterApplyEnabled"] = util.ShouldApplySyncconfAfterWrite()
	injectUILang(db, m)
	return c.Render(code, name, m)
}

func navBadgeFor(db store.IStore) int {
	if db == nil || !util.HashesChanged(db) {
		return 0
	}
	return 1
}

func injectUILang(db store.IStore, m map[string]interface{}) {
	if m == nil {
		return
	}
	lang := "es"
	if gs, ok := m["globalSettings"].(model.GlobalSetting); ok {
		lang = locale.Normalize(gs.UILanguage)
	} else if db != nil {
		if gs, err := db.GetGlobalSettings(); err == nil {
			if _, exists := m["globalSettings"]; !exists {
				m["globalSettings"] = gs
			}
			lang = locale.Normalize(gs.UILanguage)
		}
	}
	m["UILang"] = lang
	m["WGMsgJSON"] = locale.JSONForHTML(lang)
}
