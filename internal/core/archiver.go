package core

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

// ArchiveConfig holds cold archiver settings.
type ArchiveConfig struct {
	Enabled        bool         `yaml:"enabled"`
	Dir            string       `yaml:"dir"`
	RotateBytes    int64        `yaml:"rotate_bytes"`    // rotate file after N bytes (default 100MB)
	RotateInterval string       `yaml:"rotate_interval"` // rotate after duration (default "1h")
	Compress       bool         `yaml:"compress"`        // gzip compress (default true)
	SampleRules    []SampleRule `yaml:"sample_rules"`    // optional sampling for high-volume types
}

// SampleRule defines a sampling rate for specific event types or severity levels.
// Keep 1 in every N events matching the criteria. N=1 means keep all.
type SampleRule struct {
	EventType   string `yaml:"event_type"`   // event type glob (e.g., "dns_query", "http_request")
	MaxSeverity string `yaml:"max_severity"` // only sample events AT OR BELOW this severity (default: INFO)
	SampleRate  int    `yaml:"sample_rate"`  // keep 1 in N (e.g., 100 = keep 1%)
}

// DefaultArchiveConfig returns sane defaults for the cold archiver.
func DefaultArchiveConfig() ArchiveConfig {
	return ArchiveConfig{
		Enabled:        false,
		Dir:            "./data/archive",
		RotateBytes:    100 * 1024 * 1024, // 100MB
		RotateInterval: "1h",
		Compress:       true,
	}
}

// Archiver consumes events and alerts from JetStream and writes them to
// compressed NDJSON files for indefinite cold retention.
type Archiver struct {
	cfg    ArchiveConfig
	bus    *EventBus
	logger zerolog.Logger

	mu             sync.Mutex
	currentFile    *os.File
	currentGz      *gzip.Writer
	currentPath    string
	currentBytes   int64
	rotateInterval time.Duration
	fileOpenedAt   time.Time

	// Metrics
	eventsArchived int64
	alertsArchived int64
	filesRotated   int64
	bytesWritten   int64
	eventsSampled  int64            // events dropped by sampling
	sampleCounters map[string]int64 // per-type counters for sampling
}

// NewArchiver creates a cold archiver.
func NewArchiver(cfg ArchiveConfig, bus *EventBus, logger zerolog.Logger) (*Archiver, error) {
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, fmt.Errorf("creating archive dir %s: %w", cfg.Dir, err)
	}
	if err := RestrictPrivatePath(cfg.Dir, true); err != nil {
		return nil, fmt.Errorf("securing archive dir: %w", err)
	}
	entries, err := os.ReadDir(cfg.Dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), "1sec-archive-") && (strings.HasSuffix(entry.Name(), ".ndjson") || strings.HasSuffix(entry.Name(), ".ndjson.gz")) {
			if err := RestrictPrivatePath(filepath.Join(cfg.Dir, entry.Name()), false); err != nil {
				return nil, fmt.Errorf("securing existing archive: %w", err)
			}
		}
	}

	interval := time.Hour
	if d, err := time.ParseDuration(cfg.RotateInterval); err == nil && d > 0 {
		interval = d
	}

	if cfg.RotateBytes <= 0 {
		cfg.RotateBytes = 100 * 1024 * 1024
	}

	return &Archiver{
		cfg:            cfg,
		bus:            bus,
		logger:         logger.With().Str("component", "archiver").Logger(),
		rotateInterval: interval,
		sampleCounters: make(map[string]int64),
	}, nil
}

// Start subscribes to events and alerts with a separate durable consumer.
func (a *Archiver) Start(ctx context.Context) error {
	// Subscribe to all events
	if err := a.bus.Subscribe("sec.events.>", "1sec-cold-archive-events", func(msg *nats.Msg) {
		if a.shouldSample(msg.Data) {
			a.mu.Lock()
			a.eventsSampled++
			a.mu.Unlock()
			_ = msg.Ack()
			return
		}
		a.writeRecord("event", msg.Data)
		_ = msg.Ack()
	}); err != nil {
		return fmt.Errorf("archiver subscribing to events: %w", err)
	}

	// Subscribe to all alerts
	if err := a.bus.Subscribe("sec.alerts.>", "1sec-cold-archive-alerts", func(msg *nats.Msg) {
		a.writeRecord("alert", msg.Data)
		_ = msg.Ack()
	}); err != nil {
		return fmt.Errorf("archiver subscribing to alerts: %w", err)
	}

	// Subscribe to responses
	if err := a.bus.Subscribe("sec.responses.>", "1sec-cold-archive-responses", func(msg *nats.Msg) {
		a.writeRecord("response", msg.Data)
		_ = msg.Ack()
	}); err != nil {
		return fmt.Errorf("archiver subscribing to responses: %w", err)
	}

	// Rotation ticker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				a.closeFile()
				return
			case <-ticker.C:
				a.mu.Lock()
				if a.currentFile != nil && time.Since(a.fileOpenedAt) >= a.rotateInterval {
					a.rotateFileLocked()
				}
				a.mu.Unlock()
			}
		}
	}()

	a.logger.Info().
		Str("dir", a.cfg.Dir).
		Str("rotate_interval", a.rotateInterval.String()).
		Int64("rotate_bytes", a.cfg.RotateBytes).
		Bool("compress", a.cfg.Compress).
		Msg("cold archiver started")

	return nil
}

// archiveRecord is the NDJSON envelope written to archive files.
type archiveRecord struct {
	Type      string          `json:"type"` // "event", "alert", "response"
	Timestamp time.Time       `json:"ts"`
	Data      json.RawMessage `json:"data"`
}

func (a *Archiver) writeRecord(recordType string, data []byte) {
	rec := archiveRecord{
		Type:      recordType,
		Timestamp: time.Now().UTC(),
		Data:      json.RawMessage(data),
	}

	line, err := json.Marshal(rec)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to marshal archive record")
		return
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.currentFile == nil {
		if err := a.openFileLocked(); err != nil {
			a.logger.Error().Err(err).Msg("failed to open archive file")
			return
		}
	}

	var n int
	if a.cfg.Compress && a.currentGz != nil {
		n, err = a.currentGz.Write(line)
	} else {
		n, err = a.currentFile.Write(line)
	}
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to write archive record")
		return
	}

	a.currentBytes += int64(n)
	a.bytesWritten += int64(n)

	switch recordType {
	case "event":
		a.eventsArchived++
	case "alert":
		a.alertsArchived++
	}

	// Rotate on size
	if a.currentBytes >= a.cfg.RotateBytes {
		a.rotateFileLocked()
	}
}

func (a *Archiver) openFileLocked() error {
	ts := time.Now().UTC().Format("20060102T150405Z")
	ext := ".ndjson"
	if a.cfg.Compress {
		ext = ".ndjson.gz"
	}
	filename := fmt.Sprintf("1sec-archive-%s%s", ts, ext)
	path := filepath.Join(a.cfg.Dir, filename)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if err := RestrictPrivatePath(f.Name(), false); err != nil {
		f.Close()
		return err
	}

	a.currentFile = f
	a.currentPath = path
	a.currentBytes = 0
	a.fileOpenedAt = time.Now()

	if a.cfg.Compress {
		a.currentGz, _ = gzip.NewWriterLevel(f, gzip.BestSpeed)
	}

	a.logger.Debug().Str("file", filename).Msg("opened archive file")
	return nil
}

func (a *Archiver) rotateFileLocked() {
	a.closeFileLocked()
	a.filesRotated++
	// Next write will open a new file
}

func (a *Archiver) closeFile() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closeFileLocked()
}

func (a *Archiver) closeFileLocked() {
	if a.currentGz != nil {
		a.currentGz.Close()
		a.currentGz = nil
	}
	if a.currentFile != nil {
		a.currentFile.Close()
		a.currentFile = nil
	}
}

// shouldSample returns true if this event should be DROPPED (not archived)
// based on sampling rules. Only events are sampled; alerts and responses are
// always archived.
func (a *Archiver) shouldSample(data []byte) bool {
	if len(a.cfg.SampleRules) == 0 {
		return false
	}

	// Quick parse — only extract type and severity
	var partial struct {
		Type     string `json:"type"`
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(data, &partial); err != nil {
		return false // can't parse → keep it
	}

	for _, rule := range a.cfg.SampleRules {
		if rule.SampleRate <= 1 {
			continue // rate 1 = keep all
		}
		if rule.EventType != "" && rule.EventType != partial.Type {
			continue
		}
		// Check severity threshold — only sample events at or below max_severity
		maxSev := ParseSeverity(rule.MaxSeverity)
		eventSev := ParseSeverity(partial.Severity)
		if eventSev > maxSev {
			continue // event is above threshold → always keep
		}

		// Increment counter and check if this one should be kept
		a.mu.Lock()
		key := rule.EventType + ":" + rule.MaxSeverity
		a.sampleCounters[key]++
		count := a.sampleCounters[key]
		a.mu.Unlock()

		if count%int64(rule.SampleRate) != 0 {
			return true // drop this one
		}
		return false // keep this one (1 in N)
	}

	return false
}

// Status returns archiver metrics for the API.
func (a *Archiver) Status() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]interface{}{
		"enabled":         a.cfg.Enabled,
		"dir":             a.cfg.Dir,
		"events_archived": a.eventsArchived,
		"alerts_archived": a.alertsArchived,
		"events_sampled":  a.eventsSampled,
		"files_rotated":   a.filesRotated,
		"bytes_written":   a.bytesWritten,
		"current_file":    filepath.Base(a.currentPath),
		"current_bytes":   a.currentBytes,
		"compress":        a.cfg.Compress,
	}
}
