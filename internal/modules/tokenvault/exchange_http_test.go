package tokenvault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func exchangeVault(t *testing.T, handler http.HandlerFunc) *TokenVault {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	cfg := core.DefaultConfig()
	cfg.TokenVault.Auth0Domain = strings.TrimPrefix(server.URL, "https://")
	cfg.TokenVault.Auth0ClientID = "client"
	cfg.TokenVault.Auth0ClientSecret = "client-secret"
	for _, key := range []string{"AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET"} {
		t.Setenv(key, "")
	}
	tv := NewTokenVault(context.Background(), core.NewAlertPipeline(zerolog.Nop(), 10), cfg, zerolog.Nop())
	if tv.httpClient.Timeout != 15*time.Second {
		t.Fatal("exchange deadline missing")
	}
	tv.httpClient.Transport = server.Client().Transport
	return tv
}

func TestExchangeTokenRejectsInvalidSuccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"empty", 200, `{}`}, {"null", 200, `null`},
		{"missing-type", 200, `{"access_token":"token"}`},
		{"blank-token", 200, `{"access_token":" ","token_type":"Bearer"}`},
		{"control-token", 200, `{"access_token":"\u0000","token_type":"Bearer"}`},
		{"unicode-token", 200, `{"access_token":"\u2603","token_type":"Bearer"}`},
		{"control-type", 200, `{"access_token":"token","token_type":"Bearer\r\n"}`},
		{"space-type", 200, `{"access_token":"token","token_type":"Bear er"}`},
		{"negative-expiry", 200, `{"access_token":"token","token_type":"Bearer","expires_in":-1}`},
		{"server-error", 500, `{"access_token":"token","token_type":"Bearer"}`},
		{"redirect-without-location", 302, `{}`},
		{"padding", 200, `{"access_token":"token","token_type":"Bearer"}` + strings.Repeat(" ", 64<<10)},
		{"trailing-json", 200, `{"access_token":"token","token_type":"Bearer"}{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tv := exchangeVault(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			if _, err := tv.ExchangeToken("subject", SubjectTokenTypeRefreshToken, "github", ""); err == nil {
				t.Fatal("invalid response accepted")
			}
			stats := tv.exchangeTracker.Stats()
			if stats.SuccessCount != 0 || stats.FailureCount != 1 {
				t.Fatalf("incorrect exchange state: %+v", stats)
			}
		})
	}
}

func TestExchangeTokenSuccessAndOAuthError(t *testing.T) {
	for _, subjectType := range []string{SubjectTokenTypeRefreshToken, SubjectTokenTypeAccessToken} {
		t.Run(subjectType, func(t *testing.T) {
			tv := exchangeVault(t, func(w http.ResponseWriter, r *http.Request) {
				var payload TokenExchangeRequest
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if payload.SubjectTokenType != subjectType || payload.ClientSecret != "client-secret" || payload.SubjectToken != "subject" || r.URL.Path != "/oauth/token" {
					t.Errorf("changed request contract: %+v", payload)
				}
				_, _ = io.WriteString(w, `{"access_token":"token","token_type":"Bearer"}`)
			})
			result, err := tv.ExchangeToken("subject", subjectType, "github", "")
			if err != nil || result.AccessToken != "token" || tv.exchangeTracker.Stats().SuccessCount != 1 {
				t.Fatalf("valid exchange failed: %v", err)
			}
		})
	}
	tv := exchangeVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"expired"}`)
	})
	result, err := tv.ExchangeToken("subject", SubjectTokenTypeRefreshToken, "github", "")
	if err == nil || result == nil || result.Error != "invalid_grant" || tv.exchangeTracker.Stats().FailureCount != 1 {
		t.Fatalf("OAuth error contract lost: %v %+v", err, result)
	}
}

func TestExchangeTokenDoesNotReplaySecrets(t *testing.T) {
	for _, status := range []int{307, 308} {
		var received atomic.Int32
		sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
		tv := exchangeVault(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", sink.URL)
			w.WriteHeader(status)
		})
		_, err := tv.ExchangeToken("subject", SubjectTokenTypeRefreshToken, "github", "")
		sink.Close()
		if err == nil || received.Load() != 0 {
			t.Fatal("token exchange followed another origin")
		}
	}
}
