package core

import (
	"bytes"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}
var alertWebhookClient = newWebhookHTTPClient()

func httpPost(url, contentType string, body []byte) (*http.Response, error) {
	return alertWebhookClient.Post(url, contentType, bytes.NewReader(body))
}

func newAuthRequest(method, url string, body []byte, apiKey string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	return req, nil
}
