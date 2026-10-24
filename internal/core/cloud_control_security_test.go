package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloudRemoteControlRequiresOptIn(t *testing.T) {
	engine := testEngineForPoller(t, false)
	engine.Config.Cloud.RemoteCommandsEnabled = false
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	engine.Config.Cloud.APIURL = server.URL
	poller := NewCommandPoller(engine)
	poller.Start()
	poller.poll()
	poller.Stop()
	if requests.Load() != 0 {
		t.Fatal("telemetry configuration must not grant remote control")
	}
	if DefaultConfig().Cloud.RemoteCommandsEnabled {
		t.Fatal("remote control must default to off")
	}
}

func TestCloudCommandsRejectWrongInstanceExpiredAndUnscoped(t *testing.T) {
	for _, variant := range []string{"foreign", "expired", "unscoped", "malformed-expiry", "already-claimed"} {
		t.Run(variant, func(t *testing.T) {
			engine := testEngineForPoller(t, false)
			command := CloudCommand{ID: "fixture", InstanceID: "i-test", Status: "pending", Type: "set_dry_run", DryRun: boolPtr(true), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
			switch variant {
			case "foreign":
				command.InstanceID = "i-other"
			case "unscoped":
				command.InstanceID = ""
			case "expired":
				command.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339)
			case "malformed-expiry":
				command.ExpiresAt = "invalid"
			case "already-claimed":
				command.Status = "acknowledged"
			}
			var acks atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					json.NewEncoder(w).Encode(CloudCommandsResponse{Commands: []CloudCommand{command}})
				} else {
					acks.Add(1)
				}
			}))
			defer server.Close()
			engine.Config.Cloud.APIURL = server.URL
			poller := NewCommandPoller(engine)
			defer poller.Stop()
			poller.poll()
			if engine.Config.Enforcement.GetDryRun() || acks.Load() != 0 {
				t.Fatal("unsafe command was claimed or executed")
			}
		})
	}
}

func TestCloudCommandClaimConflictPreventsExecution(t *testing.T) {
	engine := testEngineForPoller(t, false)
	var patches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(CloudCommandsResponse{Commands: []CloudCommand{{ID: "fixture", InstanceID: "i-test", Status: "pending", Type: "set_dry_run", DryRun: boolPtr(true), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}}})
		} else {
			patches.Add(1)
			w.WriteHeader(http.StatusConflict)
		}
	}))
	defer server.Close()
	engine.Config.Cloud.APIURL = server.URL
	poller := NewCommandPoller(engine)
	defer poller.Stop()
	poller.poll()
	if engine.Config.Enforcement.GetDryRun() || patches.Load() != 1 {
		t.Fatal("execution must require a successful exclusive claim")
	}
}

func TestCloudCommandPaginationAndClaimToken(t *testing.T) {
	engine := testEngineForPoller(t, false)
	var claimToken string
	var gets, acks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
			if r.URL.Query().Get("instanceId") != "i-test" {
				t.Error("missing target instance")
			}
			if r.URL.Query().Get("cursor") == "" {
				json.NewEncoder(w).Encode(CloudCommandsResponse{NextCursor: "page2"})
				return
			}
			json.NewEncoder(w).Encode(CloudCommandsResponse{Commands: []CloudCommand{{ID: "fixture", InstanceID: "i-test", Status: "pending", Type: "set_dry_run", DryRun: boolPtr(true), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}}})
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["instanceId"] != "i-test" || len(body["claimToken"]) < 32 {
			t.Error("missing scoped claim proof")
		}
		if acks.Add(1) == 1 {
			claimToken = body["claimToken"]
		} else if body["claimToken"] != claimToken {
			t.Error("completion must use the original claim proof")
		}
	}))
	defer server.Close()
	engine.Config.Cloud.APIURL = server.URL
	poller := NewCommandPoller(engine)
	defer poller.Stop()
	poller.poll()
	if !engine.Config.Enforcement.GetDryRun() || gets.Load() != 2 || acks.Load() != 2 {
		t.Fatal("valid paginated command did not complete")
	}
}

func TestCloudConfiguredIdentity(t *testing.T) {
	if got := cloudInstanceID(CloudConfig{InstanceID: "i-enrolled"}); got != "i-enrolled" {
		t.Fatalf("identity changed: %s", got)
	}
	if got := cloudInstanceID(CloudConfig{}); got == "" {
		t.Fatal("legacy telemetry requires a fallback identity")
	}
}
