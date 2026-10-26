package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestWebhookDispatcher_SuccessfulDelivery(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	cfg := DefaultWebhookRetryConfig()
	cfg.Workers = 2
	cfg.QueueSize = 10

	d := newTestWebhookDispatcher(logger, cfg)
	defer d.Stop()

	id := d.Enqueue(server.URL, map[string]interface{}{"test": true}, nil)
	if id == "" {
		t.Fatal("expected non-empty delivery ID")
	}

	// Wait for delivery
	time.Sleep(500 * time.Millisecond)

	if received.Load() != 1 {
		t.Errorf("expected 1 delivery, got %d", received.Load())
	}

	stats := d.Stats()
	if stats["dead_letters"].(int) != 0 {
		t.Errorf("expected 0 dead letters, got %v", stats["dead_letters"])
	}
}

func TestWebhookDispatcher_RetryOn5xx(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	cfg := WebhookRetryConfig{
		MaxRetries:     5,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
		QueueSize:      10,
		Workers:        1,
		CircuitBreaker: 100, // high threshold so it doesn't trip
		CircuitPause:   1 * time.Second,
	}

	d := newTestWebhookDispatcher(logger, cfg)
	defer d.Stop()

	d.Enqueue(server.URL, map[string]interface{}{"retry": true}, nil)

	time.Sleep(2 * time.Second)

	if attempts.Load() < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts.Load())
	}
}

func TestWebhookDispatcher_DeadLetterOn4xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	cfg := DefaultWebhookRetryConfig()
	cfg.Workers = 1
	cfg.InitialBackoff = 10 * time.Millisecond

	d := newTestWebhookDispatcher(logger, cfg)
	defer d.Stop()

	d.Enqueue(server.URL, map[string]interface{}{"bad": true}, nil)

	time.Sleep(500 * time.Millisecond)

	dls := d.GetDeadLetters(10)
	if len(dls) != 1 {
		t.Errorf("expected 1 dead letter, got %d", len(dls))
	}
}

func TestWebhookDispatcher_RetryDeadLetter(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	cfg := DefaultWebhookRetryConfig()
	cfg.Workers = 1
	cfg.InitialBackoff = 10 * time.Millisecond

	d := newTestWebhookDispatcher(logger, cfg)
	defer d.Stop()

	d.Enqueue(server.URL, map[string]interface{}{"test": true}, nil)
	time.Sleep(500 * time.Millisecond)

	dls := d.GetDeadLetters(10)
	if len(dls) != 1 {
		t.Fatalf("expected 1 dead letter, got %d", len(dls))
	}

	ok := d.RetryDeadLetter(dls[0].Delivery.ID)
	if !ok {
		t.Fatal("RetryDeadLetter returned false")
	}

	time.Sleep(500 * time.Millisecond)

	dls = d.GetDeadLetters(10)
	if len(dls) != 0 {
		t.Errorf("expected 0 dead letters after retry, got %d", len(dls))
	}
}

func TestWebhookDispatcher_CustomHeaders(t *testing.T) {
	headerCh := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerCh <- r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	cfg := DefaultWebhookRetryConfig()
	cfg.Workers = 1

	d := newTestWebhookDispatcher(logger, cfg)
	defer d.Stop()

	d.Enqueue(server.URL, map[string]interface{}{}, map[string]string{"X-Custom": "test-value"})

	select {
	case gotHeader := <-headerCh:
		if gotHeader != "test-value" {
			t.Errorf("expected custom header 'test-value', got %q", gotHeader)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery")
	}
}

func TestWebhookDispatcher_PayloadIntegrity(t *testing.T) {
	payloadCh := make(chan map[string]interface{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]interface{}
		json.NewDecoder(r.Body).Decode(&p)
		payloadCh <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	cfg := DefaultWebhookRetryConfig()
	cfg.Workers = 1

	d := newTestWebhookDispatcher(logger, cfg)
	defer d.Stop()

	payload := map[string]interface{}{
		"alert_id": "test-123",
		"severity": "CRITICAL",
	}
	d.Enqueue(server.URL, payload, nil)

	select {
	case receivedPayload := <-payloadCh:
		if receivedPayload["alert_id"] != "test-123" {
			t.Errorf("payload mismatch: %v", receivedPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery")
	}
}

func newTestWebhookDispatcher(logger zerolog.Logger, cfg WebhookRetryConfig) *WebhookDispatcher {
	cfg.client = &http.Client{Timeout: time.Second}
	return NewWebhookDispatcher(logger, cfg)
}
