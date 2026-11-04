package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCloudHTTPDeliveryBoundary(t *testing.T) {
	for _, status := range []int{204, 302, 307, 500} {
		var received atomic.Int32
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status == 307 {
				w.Header().Set("Location", sink.URL)
			}
			w.WriteHeader(status)
		}))
		cfg := DefaultConfig()
		cfg.Cloud.APIURL = server.URL
		cfg.Cloud.APIKey = "key"
		cr := &CloudReporter{cfg: cfg}
		cp := &CommandPoller{cfg: cfg}
		for name, err := range map[string]error{"ingest": cr.postIngest(map[string]string{"private": "event"}), "ack": cp.ackCommand("id", "executed", "", "")} {
			if (err == nil) != (status == 204) {
				t.Errorf("%s HTTP %d: %v", name, status, err)
			}
		}
		server.Close()
		sink.Close()
		if received.Load() != 0 {
			t.Fatal("cloud event/ACK crossed origins")
		}
	}
}

func TestCloudCommandResponseRejectsPadding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"commands":[{"id":"not-admitted"}]}`+strings.Repeat(" ", 2<<20))
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Cloud.APIURL = server.URL
	cp := &CommandPoller{cfg: cfg, ctx: context.Background()}
	commands, err := cp.fetchPendingCommands()
	if err == nil || len(commands) != 0 {
		t.Fatal("accepted command prefix from oversized response")
	}
}
