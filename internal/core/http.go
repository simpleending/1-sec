package core

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var httpClient = NewAuthenticatedHTTPClient(10 * time.Second)
var alertWebhookClient = newWebhookHTTPClient()

// NewAuthenticatedHTTPClient keeps credentials and replayable bodies within the
// original origin. Same-origin API moves are supported, with Go's redirect cap.
func NewAuthenticatedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		if len(via) == 0 || req.URL.User != nil || !sameHTTPOrigin(via[0].URL, req.URL) {
			return fmt.Errorf("authenticated request cannot redirect to another origin")
		}
		return nil
	}}
}

func sameHTTPOrigin(a, b *url.URL) bool {
	// DNS case folding is ASCII-only. Unicode EqualFold can equate distinct
	// IDNA names (e.g. Greek sigma and final sigma) before transport encoding.
	// Keep non-ASCII spelling exact rather than broaden origin authority.
	host := func(u *url.URL) string {
		return strings.Map(func(c rune) rune {
			if c >= 'A' && c <= 'Z' {
				return c + ('a' - 'A')
			}
			return c
		}, u.Hostname())
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		host(a) == host(b) && port(a) == port(b)
}

// ReadBoundedResponse rejects an oversized response, including valid JSON
// prefixes followed by padding. Callers must close the response body.
func ReadBoundedResponse(body io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 || limit == math.MaxInt64 {
		return nil, fmt.Errorf("invalid response limit")
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

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
