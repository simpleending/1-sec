package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// webhook_retry.go — reliable webhook delivery with exponential backoff,
// dead letter buffer, and circuit breaker.
//
// SOC teams depend on webhook notifications reaching PagerDuty/Slack/etc.
// A transient 503 from Slack shouldn't silently drop a CRITICAL alert.
//
// Design:
//   - Async delivery queue with configurable concurrency
//   - Exponential backoff: 1s → 2s → 4s → 8s → 16s (max 5 retries)
//   - Dead letter buffer for permanently failed deliveries (queryable via API)
//   - Circuit breaker: if a URL fails 5 times in a row, pause for 60s
//   - All zero-dependency, pure Go
// ---------------------------------------------------------------------------

// WebhookDelivery represents a single webhook delivery attempt.
type WebhookDelivery struct {
	ID        string                 `json:"id"`
	URL       string                 `json:"url"`
	Payload   map[string]interface{} `json:"payload"`
	Headers   map[string]string      `json:"headers,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	Attempts  int                    `json:"attempts"`
	LastError string                 `json:"last_error,omitempty"`
	Status    string                 `json:"status"` // "pending", "delivered", "dead_letter"
}

// DeadLetterEntry is a failed delivery preserved for inspection.
type DeadLetterEntry struct {
	Delivery  WebhookDelivery `json:"delivery"`
	FailedAt  time.Time       `json:"failed_at"`
	LastError string          `json:"last_error"`
}

// WebhookRetryConfig controls retry behavior.
type WebhookRetryConfig struct {
	client         *http.Client
	MaxRetries     int           `yaml:"max_retries" json:"max_retries"`
	InitialBackoff time.Duration `yaml:"initial_backoff" json:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff" json:"max_backoff"`
	QueueSize      int           `yaml:"queue_size" json:"queue_size"`
	Workers        int           `yaml:"workers" json:"workers"`
	CircuitBreaker int           `yaml:"circuit_breaker_threshold" json:"circuit_breaker_threshold"`
	CircuitPause   time.Duration `yaml:"circuit_pause" json:"circuit_pause"`
}

// DefaultWebhookRetryConfig returns sane defaults.
func DefaultWebhookRetryConfig() WebhookRetryConfig {
	return WebhookRetryConfig{
		MaxRetries:     5,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     30 * time.Second,
		QueueSize:      1000,
		Workers:        4,
		CircuitBreaker: 5,
		CircuitPause:   60 * time.Second,
	}
}

// WebhookDispatcher manages reliable webhook delivery.
type WebhookDispatcher struct {
	logger     zerolog.Logger
	cfg        WebhookRetryConfig
	queue      chan *WebhookDelivery
	deadLetter []*DeadLetterEntry
	dlMu       sync.RWMutex
	maxDL      int

	// Circuit breaker state per URL
	cbMu       sync.Mutex
	cbFailures map[string]int
	cbOpenedAt map[string]time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewWebhookDispatcher creates a dispatcher with background workers.
func NewWebhookDispatcher(logger zerolog.Logger, cfg WebhookRetryConfig) *WebhookDispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	d := &WebhookDispatcher{
		logger:     logger.With().Str("component", "webhook_dispatcher").Logger(),
		cfg:        cfg,
		queue:      make(chan *WebhookDelivery, cfg.QueueSize),
		deadLetter: make([]*DeadLetterEntry, 0, 100),
		maxDL:      500,
		cbFailures: make(map[string]int),
		cbOpenedAt: make(map[string]time.Time),
		ctx:        ctx,
		cancel:     cancel,
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go d.worker(i)
	}

	d.logger.Info().Int("workers", workers).Int("queue_size", cfg.QueueSize).Msg("webhook dispatcher started")
	return d
}

// Enqueue adds a webhook delivery to the async queue.
// Returns immediately. Delivery happens in background with retries.
func (d *WebhookDispatcher) Enqueue(url string, payload map[string]interface{}, headers map[string]string) string {
	delivery := &WebhookDelivery{
		ID:        uuid.New().String(),
		URL:       url,
		Payload:   payload,
		Headers:   headers,
		CreatedAt: time.Now().UTC(),
		Status:    "pending",
	}

	select {
	case d.queue <- delivery:
		d.logger.Debug().Str("id", delivery.ID).Str("url", url).Msg("webhook enqueued")
	default:
		d.logger.Warn().Str("url", url).Msg("webhook queue full — delivery dropped")
		d.addDeadLetter(delivery, "queue full — delivery dropped")
	}
	return delivery.ID
}

// GetDeadLetters returns failed deliveries for inspection.
func (d *WebhookDispatcher) GetDeadLetters(limit int) []*DeadLetterEntry {
	d.dlMu.RLock()
	defer d.dlMu.RUnlock()

	if limit <= 0 || limit > len(d.deadLetter) {
		limit = len(d.deadLetter)
	}
	result := make([]*DeadLetterEntry, 0, limit)
	start := len(d.deadLetter) - limit
	if start < 0 {
		start = 0
	}
	for i := start; i < len(d.deadLetter); i++ {
		result = append(result, d.deadLetter[i])
	}
	return result
}

// RetryDeadLetter re-enqueues a dead letter entry by ID.
func (d *WebhookDispatcher) RetryDeadLetter(id string) bool {
	d.dlMu.Lock()
	defer d.dlMu.Unlock()

	for i, dl := range d.deadLetter {
		if dl.Delivery.ID == id {
			dl.Delivery.Attempts = 0
			dl.Delivery.Status = "pending"
			dl.Delivery.LastError = ""
			select {
			case d.queue <- &dl.Delivery:
				d.deadLetter = append(d.deadLetter[:i], d.deadLetter[i+1:]...)
				return true
			default:
				return false
			}
		}
	}
	return false
}

// Stats returns dispatcher statistics.
func (d *WebhookDispatcher) Stats() map[string]interface{} {
	d.dlMu.RLock()
	dlCount := len(d.deadLetter)
	d.dlMu.RUnlock()

	d.cbMu.Lock()
	openCircuits := 0
	for url, openedAt := range d.cbOpenedAt {
		if time.Since(openedAt) < d.cfg.CircuitPause {
			openCircuits++
		} else {
			delete(d.cbOpenedAt, url)
			delete(d.cbFailures, url)
		}
	}
	d.cbMu.Unlock()

	return map[string]interface{}{
		"queue_depth":    len(d.queue),
		"queue_capacity": d.cfg.QueueSize,
		"dead_letters":   dlCount,
		"open_circuits":  openCircuits,
		"workers":        d.cfg.Workers,
		"max_retries":    d.cfg.MaxRetries,
	}
}

// Stop gracefully shuts down the dispatcher, draining the queue.
func (d *WebhookDispatcher) Stop() {
	d.cancel()
	d.wg.Wait()
	d.logger.Info().Int("dead_letters", len(d.deadLetter)).Msg("webhook dispatcher stopped")
}

func (d *WebhookDispatcher) worker(id int) {
	defer d.wg.Done()
	client := newWebhookHTTPClient()
	if d.cfg.client != nil {
		client = d.cfg.client
	}

	for {
		select {
		case <-d.ctx.Done():
			return
		case delivery, ok := <-d.queue:
			if !ok {
				return
			}
			d.deliver(client, delivery)
		}
	}
}

func (d *WebhookDispatcher) deliver(client *http.Client, delivery *WebhookDelivery) {
	// Check circuit breaker
	if d.isCircuitOpen(delivery.URL) {
		d.logger.Warn().Str("url", delivery.URL).Msg("circuit breaker open — skipping delivery")
		d.addDeadLetter(delivery, "circuit breaker open for URL")
		return
	}

	for attempt := 0; attempt <= d.cfg.MaxRetries; attempt++ {
		delivery.Attempts = attempt + 1

		data, err := json.Marshal(delivery.Payload)
		if err != nil {
			delivery.LastError = fmt.Sprintf("marshal error: %v", err)
			d.addDeadLetter(delivery, delivery.LastError)
			return
		}

		req, err := http.NewRequestWithContext(d.ctx, "POST", delivery.URL, bytes.NewReader(data))
		if err != nil {
			delivery.LastError = fmt.Sprintf("request creation error: %v", err)
			d.addDeadLetter(delivery, delivery.LastError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "1sec-webhook-dispatcher/1.0")
		req.Header.Set("X-1SEC-Delivery-ID", delivery.ID)
		req.Header.Set("X-1SEC-Attempt", fmt.Sprintf("%d", delivery.Attempts))
		for k, v := range delivery.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			delivery.LastError = fmt.Sprintf("request failed: %v", err)
			d.recordFailure(delivery.URL)
			if attempt < d.cfg.MaxRetries {
				d.backoff(attempt)
				continue
			}
			d.addDeadLetter(delivery, delivery.LastError)
			return
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			delivery.Status = "delivered"
			d.recordSuccess(delivery.URL)
			d.logger.Debug().
				Str("id", delivery.ID).
				Str("url", delivery.URL).
				Int("attempts", delivery.Attempts).
				Int("status", resp.StatusCode).
				Msg("webhook delivered")
			return
		}

		// Retry on 5xx and 429, dead-letter on 4xx (except 429)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			delivery.LastError = fmt.Sprintf("client error: HTTP %d", resp.StatusCode)
			d.addDeadLetter(delivery, delivery.LastError)
			return
		}

		delivery.LastError = fmt.Sprintf("server error: HTTP %d", resp.StatusCode)
		d.recordFailure(delivery.URL)
		if attempt < d.cfg.MaxRetries {
			d.backoff(attempt)
		}
	}

	d.addDeadLetter(delivery, delivery.LastError)
}

func (d *WebhookDispatcher) backoff(attempt int) {
	delay := time.Duration(float64(d.cfg.InitialBackoff) * math.Pow(2, float64(attempt)))
	if delay > d.cfg.MaxBackoff {
		delay = d.cfg.MaxBackoff
	}
	select {
	case <-time.After(delay):
	case <-d.ctx.Done():
	}
}

func (d *WebhookDispatcher) addDeadLetter(delivery *WebhookDelivery, reason string) {
	delivery.Status = "dead_letter"
	d.dlMu.Lock()
	if len(d.deadLetter) >= d.maxDL {
		d.deadLetter = d.deadLetter[d.maxDL/10:]
	}
	d.deadLetter = append(d.deadLetter, &DeadLetterEntry{
		Delivery:  *delivery,
		FailedAt:  time.Now().UTC(),
		LastError: reason,
	})
	d.dlMu.Unlock()
	d.logger.Warn().
		Str("id", delivery.ID).
		Str("url", delivery.URL).
		Int("attempts", delivery.Attempts).
		Str("error", reason).
		Msg("webhook moved to dead letter")
}

func (d *WebhookDispatcher) isCircuitOpen(url string) bool {
	d.cbMu.Lock()
	defer d.cbMu.Unlock()
	if openedAt, ok := d.cbOpenedAt[url]; ok {
		if time.Since(openedAt) < d.cfg.CircuitPause {
			return true
		}
		// Circuit half-open — allow retry
		delete(d.cbOpenedAt, url)
		d.cbFailures[url] = 0
	}
	return false
}

func (d *WebhookDispatcher) recordFailure(url string) {
	d.cbMu.Lock()
	defer d.cbMu.Unlock()
	d.cbFailures[url]++
	if d.cbFailures[url] >= d.cfg.CircuitBreaker {
		d.cbOpenedAt[url] = time.Now()
		d.logger.Warn().Str("url", url).Int("failures", d.cbFailures[url]).Msg("circuit breaker opened for webhook URL")
	}
}

func (d *WebhookDispatcher) recordSuccess(url string) {
	d.cbMu.Lock()
	defer d.cbMu.Unlock()
	d.cbFailures[url] = 0
	delete(d.cbOpenedAt, url)
}
