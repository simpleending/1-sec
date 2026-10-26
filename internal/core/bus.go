package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

// EventBus wraps NATS JetStream for event publishing and subscribing.
type EventBus struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	ns     *server.Server
	logger zerolog.Logger
	mu     sync.RWMutex
	subs   []*nats.Subscription
	token  string

	// Metrics
	metrics *BusMetrics
}

// BusMetrics tracks event bus performance counters.
type BusMetrics struct {
	mu              sync.Mutex `json:"-"`
	EventsPublished int64      `json:"events_published"`
	EventsFailed    int64      `json:"events_failed"`
	AlertsPublished int64      `json:"alerts_published"`
	MessagesAcked   int64      `json:"messages_acked"`
	MessagesNaked   int64      `json:"messages_naked"`
}

// NewEventBus creates a new EventBus. If cfg.Embedded is true, it starts an embedded NATS server.
func NewEventBus(cfg *BusConfig, logger zerolog.Logger) (*EventBus, error) {
	bus := &EventBus{
		logger:  logger.With().Str("component", "event_bus").Logger(),
		subs:    make([]*nats.Subscription, 0),
		metrics: &BusMetrics{},
	}

	if cfg.Embedded {
		if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
			return nil, fmt.Errorf("creating NATS data dir: %w", err)
		}
		if err := RestrictPrivatePath(cfg.DataDir, true); err != nil {
			return nil, fmt.Errorf("securing NATS data dir: %w", err)
		}
		var err error
		bus.token, err = ReadEmbeddedBusToken(cfg.DataDir)
		if errors.Is(err, os.ErrNotExist) {
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return nil, fmt.Errorf("creating NATS credential: %w", err)
			}
			bus.token = hex.EncodeToString(secret)
		} else if err != nil {
			return nil, err
		}

		opts := &server.Options{
			Host:          "127.0.0.1",
			Port:          cfg.Port,
			JetStream:     true,
			StoreDir:      cfg.DataDir,
			NoLog:         true,
			NoSigs:        true,
			Authorization: bus.token,
		}

		ns, err := server.NewServer(opts)
		if err != nil {
			return nil, fmt.Errorf("creating embedded NATS server: %w", err)
		}

		ns.Start()

		if !ns.ReadyForConnections(10 * time.Second) {
			return nil, fmt.Errorf("embedded NATS server failed to start within timeout")
		}

		bus.ns = ns
		if err := writeBusToken(cfg.DataDir, bus.token); err != nil {
			ns.Shutdown()
			return nil, err
		}
		bus.logger.Info().Int("port", cfg.Port).Msg("embedded NATS server started")
	}

	url := cfg.URL
	if cfg.Embedded {
		url = bus.ns.ClientURL()
	} else {
		bus.token = cfg.Token
		if bus.token == "" {
			bus.token = os.Getenv("ONESEC_NATS_TOKEN")
		}
	}

	nc, err := nats.Connect(url,
		nats.Token(bus.token),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(60),
		nats.ReconnectWait(time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				bus.logger.Warn().Err(err).Msg("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			bus.logger.Info().Msg("NATS reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS: %w", err)
	}
	bus.nc = nc

	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("creating JetStream context: %w", err)
	}
	bus.js = js

	// Create or update the main security events stream.
	// AddStream returns the existing stream if config matches; if the stream exists
	// with a different config (e.g., after a version upgrade), we update it.
	eventsStreamCfg := &nats.StreamConfig{
		Name:      "SECURITY_EVENTS",
		Subjects:  []string{"sec.events.>"},
		Retention: nats.LimitsPolicy,
		MaxAge:    24 * time.Hour * 7, // 7 days retention
		MaxBytes:  1024 * 1024 * 1024, // 1GB max
		Storage:   nats.FileStorage,
		Discard:   nats.DiscardOld,
	}
	_, err = js.AddStream(eventsStreamCfg)
	if err != nil {
		// Stream may exist with different config from a previous version — try update
		if _, updateErr := js.UpdateStream(eventsStreamCfg); updateErr != nil {
			return nil, fmt.Errorf("creating/updating events stream: %w (original: %v)", updateErr, err)
		}
	}

	// Create or update the alerts stream.
	alertsStreamCfg := &nats.StreamConfig{
		Name:      "SECURITY_ALERTS",
		Subjects:  []string{"sec.alerts.>"},
		Retention: nats.LimitsPolicy,
		MaxAge:    24 * time.Hour * 30, // 30 days retention
		MaxBytes:  512 * 1024 * 1024,   // 512MB max
		Storage:   nats.FileStorage,
		Discard:   nats.DiscardOld,
	}
	_, err = js.AddStream(alertsStreamCfg)
	if err != nil {
		if _, updateErr := js.UpdateStream(alertsStreamCfg); updateErr != nil {
			return nil, fmt.Errorf("creating/updating alerts stream: %w (original: %v)", updateErr, err)
		}
	}

	// Create or update the enforcement responses stream.
	responsesStreamCfg := &nats.StreamConfig{
		Name:      "SECURITY_RESPONSES",
		Subjects:  []string{"sec.responses.>"},
		Retention: nats.LimitsPolicy,
		MaxAge:    24 * time.Hour * 30, // 30 days retention
		MaxBytes:  256 * 1024 * 1024,   // 256MB max
		Storage:   nats.FileStorage,
		Discard:   nats.DiscardOld,
	}
	_, err = js.AddStream(responsesStreamCfg)
	if err != nil {
		if _, updateErr := js.UpdateStream(responsesStreamCfg); updateErr != nil {
			return nil, fmt.Errorf("creating/updating responses stream: %w (original: %v)", updateErr, err)
		}
	}

	bus.logger.Info().Str("url", url).Msg("connected to NATS JetStream")
	return bus, nil
}

// ReadEmbeddedBusToken lets same-account collectors join the running instance.
func ReadEmbeddedBusToken(dataDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "connection.token"))
	if err != nil {
		return "", fmt.Errorf("reading embedded NATS credential (start the engine first): %w", err)
	}
	if token := strings.TrimSpace(string(data)); len(token) == 64 {
		return token, nil
	}
	return "", fmt.Errorf("invalid embedded NATS credential")
}

func writeBusToken(dataDir, token string) error {
	f, err := os.OpenFile(filepath.Join(dataDir, "connection.token"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("creating NATS credential file: %w", err)
	}
	defer f.Close()
	if err := RestrictPrivatePath(f.Name(), false); err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteString(token); err != nil {
		return err
	}
	return f.Sync()
}

// PublishEvent publishes a SecurityEvent to the event bus.
func (b *EventBus) PublishEvent(event *SecurityEvent) error {
	CanonicalizeEventRouting(event)

	data, err := event.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}

	subject := fmt.Sprintf("sec.events.%s.%s", event.Module, event.Type)
	_, err = b.js.Publish(subject, data)
	if err != nil {
		b.metrics.mu.Lock()
		b.metrics.EventsFailed++
		b.metrics.mu.Unlock()
		return fmt.Errorf("publishing event to %s: %w", subject, err)
	}

	b.metrics.mu.Lock()
	b.metrics.EventsPublished++
	b.metrics.mu.Unlock()

	b.logger.Debug().
		Str("event_id", event.ID).
		Str("subject", subject).
		Str("severity", event.Severity.String()).
		Msg("event published")

	return nil
}

// PublishAlert publishes an Alert to the alert stream.
func (b *EventBus) PublishAlert(alert *Alert) error {
	data, err := alert.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling alert: %w", err)
	}

	subject := fmt.Sprintf("sec.alerts.%s.%s", alert.Module, alert.Severity.String())
	_, err = b.js.Publish(subject, data)
	if err != nil {
		return fmt.Errorf("publishing alert to %s: %w", subject, err)
	}

	b.metrics.mu.Lock()
	b.metrics.AlertsPublished++
	b.metrics.mu.Unlock()

	return nil
}

// Subscribe creates a durable subscription to a subject pattern.
func (b *EventBus) Subscribe(subject, durableName string, handler func(msg *nats.Msg)) error {
	opts := []nats.SubOpt{nats.DeliverNew(), nats.AckExplicit()}
	if durableName != "" {
		opts = append(opts, nats.Durable(durableName))
	}
	sub, err := b.js.Subscribe(subject, handler, opts...)
	if err != nil {
		return fmt.Errorf("subscribing to %s: %w", subject, err)
	}

	b.mu.Lock()
	b.subs = append(b.subs, sub)
	b.mu.Unlock()

	b.logger.Debug().Str("subject", subject).Str("durable", durableName).Msg("subscribed")
	return nil
}

// SubscribeToAllEvents subscribes to all security events with a durable consumer.
func (b *EventBus) SubscribeToAllEvents(handler func(event *SecurityEvent)) error {
	return b.Subscribe("sec.events.>", "1sec-engine-events", func(msg *nats.Msg) {
		event, err := UnmarshalSecurityEvent(msg.Data)
		if err != nil {
			b.logger.Error().Err(err).Msg("failed to unmarshal event")
			_ = msg.Nak()
			b.metrics.mu.Lock()
			b.metrics.MessagesNaked++
			b.metrics.mu.Unlock()
			return
		}
		handler(event)
		_ = msg.Ack()
		b.metrics.mu.Lock()
		b.metrics.MessagesAcked++
		b.metrics.mu.Unlock()
	})
}

// Close shuts down the event bus.
func (b *EventBus) Close() error {
	b.mu.Lock()
	for _, sub := range b.subs {
		_ = sub.Unsubscribe()
	}
	b.subs = nil
	b.mu.Unlock()

	if b.nc != nil {
		b.nc.Close()
	}

	if b.ns != nil {
		b.ns.Shutdown()
		b.ns.WaitForShutdown()
		b.logger.Info().Msg("embedded NATS server stopped")
	}

	return nil
}

// IsConnected returns true if the NATS connection is active.
func (b *EventBus) IsConnected() bool {
	return b.nc != nil && b.nc.IsConnected()
}

// SubscribeToRustMatches subscribes to pattern match results published by the
// Rust sidecar engine on sec.matches.>. Uses a durable consumer with explicit
// ack for reliable delivery. The SECURITY_MATCH_RESULTS stream is created by
// the Rust engine, but we ensure it exists here too in case Go starts first.
func (b *EventBus) SubscribeToRustMatches(handler func(data []byte)) error {
	// Ensure the match results stream exists (Rust also creates it, but Go may start first)
	matchStreamCfg := &nats.StreamConfig{
		Name:      "SECURITY_MATCH_RESULTS",
		Subjects:  []string{"sec.matches.>"},
		Retention: nats.LimitsPolicy,
		MaxAge:    24 * time.Hour * 7, // 7 days
		MaxBytes:  512 * 1024 * 1024,  // 512MB
		Storage:   nats.FileStorage,
		Discard:   nats.DiscardOld,
	}
	_, err := b.js.AddStream(matchStreamCfg)
	if err != nil {
		if _, updateErr := b.js.UpdateStream(matchStreamCfg); updateErr != nil {
			b.logger.Warn().Err(updateErr).Msg("could not create/update match results stream — Rust engine may create it")
		}
	}

	return b.Subscribe("sec.matches.>", "1sec-rust-matches", func(msg *nats.Msg) {
		handler(msg.Data)
		_ = msg.Ack()
	})
}

// GetMetrics returns a snapshot of bus metrics.
func (b *EventBus) GetMetrics() map[string]int64 {
	b.metrics.mu.Lock()
	defer b.metrics.mu.Unlock()
	return map[string]int64{
		"events_published": b.metrics.EventsPublished,
		"events_failed":    b.metrics.EventsFailed,
		"alerts_published": b.metrics.AlertsPublished,
		"messages_acked":   b.metrics.MessagesAcked,
		"messages_naked":   b.metrics.MessagesNaked,
	}
}
