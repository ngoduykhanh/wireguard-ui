package handler

type jsonHTTPResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

// jsonHTTPReauthenticate is returned when the server cleared the session but the client must go to /login.
type jsonHTTPReauthenticate struct {
	Status         bool   `json:"status"`
	Message        string `json:"message"`
	Reauthenticate bool   `json:"reauthenticate,omitempty"`
}
