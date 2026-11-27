package core

import (
	"net/http"
	"testing"
)

func TestCloudCredentialDestinations(t *testing.T) {
	for _, example := range []struct {
		url   string
		valid bool
	}{
		{"https://example.test/api", true},
		{"http://127.0.0.1:8080/api", true},
		{"http://[::1]:8080/api", true},
		{"http://example.test/api", false},
		{"https://name:password@example.test/api", false},
		{"https:///api", false},
	} {
		req, err := newAuthRequest(http.MethodPost, example.url, nil, "fixture")
		if (err == nil) != example.valid {
			t.Errorf("%s: allowed=%v, want %v", example.url, err == nil, example.valid)
		}
		if req != nil && req.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("valid cloud request lost authentication")
		}
	}
}
