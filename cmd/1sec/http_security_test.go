package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCLIAuthenticatedRedirects(t *testing.T) {
	for name, call := range map[string]func(string) error{
		"get":    func(u string) error { _, err := apiGet(u, "key", time.Second); return err },
		"post":   func(u string) error { _, err := apiPost(u, []byte("private"), "key", time.Second); return err },
		"patch":  func(u string) error { _, err := apiPatch(u, []byte("private"), "key", time.Second); return err },
		"delete": func(u string) error { _, err := apiDelete(u, "key", time.Second); return err },
		"stream-get": func(u string) error {
			r, err := doGet(u, "key")
			if err == nil {
				r.Body.Close()
			}
			return err
		},
		"stream-post": func(u string) error {
			r, err := doPost(u, "key", []byte("private"))
			if err == nil {
				r.Body.Close()
			}
			return err
		},
		"restore": func(u string) error { return postRestore(u, "key", []byte("private")) },
	} {
		t.Run(name, func(t *testing.T) {
			var received atomic.Int32
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
			defer sink.Close()
			issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Location", sink.URL); w.WriteHeader(307) }))
			defer issuer.Close()
			if err := call(issuer.URL); err == nil || received.Load() != 0 {
				t.Fatal("CLI request followed another origin")
			}
		})
	}
}

func TestRestoreRequiresDeliverySuccess(t *testing.T) {
	for _, status := range []int{204, 302, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		err := postRestore(server.URL, "key", []byte("{}"))
		server.Close()
		if (err == nil) != (status == 204) {
			t.Fatalf("HTTP %d: %v", status, err)
		}
	}
}
