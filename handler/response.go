package handler

type jsonHTTPResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}
