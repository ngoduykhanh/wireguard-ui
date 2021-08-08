package util

// Runtime config
var (
	DisableLogin   bool
	BindAddress    string
	SendgridApiKey string
	EmailFrom      string
	EmailFromName  string
	EmailSubject   string
	EmailContent   string
	SessionSecret  []byte
)
