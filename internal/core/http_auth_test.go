package core

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthenticatedRedirectRejectsUnicodeFoldAlias(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "http://ς.example/sink")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		received.Add(1)
	}))
	defer server.Close()
	client := NewAuthenticatedHTTPClient(time.Second)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	client.Transport = transport
	req, _ := http.NewRequest(http.MethodPost, "http://σ.example/start", strings.NewReader("secret-body"))
	req.Header.Set("x-goog-api-key", "fake-secret")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Error("distinct IDNA origin accepted")
	}
	if received.Load() != 0 {
		t.Fatal("sensitive request reached a distinct IDNA origin")
	}
}

func TestAuthenticatedHTTPClientRejectsCrossOrigin(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var received atomic.Int32
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer sink.Close()
			issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", sink.URL)
				w.WriteHeader(status)
			}))
			defer issuer.Close()
			req, _ := http.NewRequest(http.MethodPost, issuer.URL, strings.NewReader("subject_token=secret"))
			req.Header.Set("Authorization", "Bearer secret")
			req.Header.Set("x-goog-api-key", "secret-key")
			resp, err := NewAuthenticatedHTTPClient(time.Second).Do(req)
			if err == nil {
				resp.Body.Close()
				t.Error("cross-origin redirect accepted")
			}
			if received.Load() != 0 {
				t.Fatal("redirect destination received a credential-bearing request")
			}
		})
	}
}

func TestAuthenticatedRedirectPolicyOrigins(t *testing.T) {
	client := NewAuthenticatedHTTPClient(time.Second)
	for _, tc := range []struct {
		from, to string
		allowed  bool
	}{
		{"https://example.com/a", "https://EXAMPLE.com:443/b", true},
		{"http://example.com/a", "http://example.com:80/b", true},
		{"https://example.com/a", "http://example.com/b", false},
		{"https://example.com/a", "https://sub.example.com/b", false},
		{"https://example.com/a", "https://example.com:444/b", false},
		{"https://example.com/a", "https://user:password@example.com/b", false},
		{"https://σ.example/a", "https://ς.example/b", false},
		{"https://σ.example/a", "https://σ.example/b", true},
	} {
		from, _ := http.NewRequest(http.MethodGet, tc.from, nil)
		to, _ := http.NewRequest(http.MethodGet, tc.to, nil)
		err := client.CheckRedirect(to, []*http.Request{from})
		if (err == nil) != tc.allowed {
			t.Errorf("%s -> %s: %v", tc.from, tc.to, err)
		}
	}
	u, _ := url.Parse("https://example.com")
	req := &http.Request{URL: u}
	if client.CheckRedirect(req, make([]*http.Request, 10)) == nil {
		t.Fatal("redirect cap missing")
	}
}

func TestReadBoundedResponse(t *testing.T) {
	for _, size := range []int{7, 8, 9} {
		got, err := ReadBoundedResponse(strings.NewReader(strings.Repeat(" ", size)), 8)
		if size > 8 {
			if err == nil || got != nil {
				t.Fatal("oversize body returned")
			}
		} else if err != nil || len(got) != size {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

func TestAuthenticatedHTTPClientSameOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/finish")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || string(body) != "payload" || r.Header.Get("Authorization") != "Bearer key" {
			t.Error("same-origin request lost method, body or credentials")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := NewAuthenticatedHTTPClient(time.Second)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/start", strings.NewReader("payload"))
	req.Header.Set("Authorization", "Bearer key")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal(resp.Status)
	}
}
