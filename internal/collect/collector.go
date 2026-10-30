package collect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// Collector is the interface for all reference collectors.
type Collector interface {
	Name() string
	Start(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) error
	Stop() error
}

// CollectorConfig holds settings for a single collector instance.
type CollectorConfig struct {
	Type    string `yaml:"type"`     // "nginx", "authlog", "pfsense", "jsonlog"
	LogPath string `yaml:"log_path"` // path to the log file to tail
	Tag     string `yaml:"tag"`      // optional tag for source identification
}

// CollectorsConfig holds the top-level collectors configuration.
type CollectorsConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Collectors []CollectorConfig `yaml:"sources"`
}

// Manager manages multiple collector instances.
type Manager struct {
	mu         sync.Mutex
	collectors []Collector
	logger     zerolog.Logger
}

// NewManager creates a collector manager.
func NewManager(logger zerolog.Logger) *Manager {
	return &Manager{
		logger: logger.With().Str("component", "collector_manager").Logger(),
	}
}

// StartAll creates and starts collectors from config.
func (m *Manager) StartAll(ctx context.Context, cfg CollectorsConfig, bus *core.EventBus) error {
	for _, cc := range cfg.Collectors {
		var c Collector
		switch cc.Type {
		case "nginx":
			c = NewNginxCollector(cc.LogPath, cc.Tag)
		case "authlog":
			c = NewAuthLogCollector(cc.LogPath, cc.Tag)
		case "pfsense":
			c = NewPfSenseCollector(cc.LogPath, cc.Tag)
		case "jsonlog":
			c = NewJSONLogCollector(cc.LogPath, cc.Tag)
		case "github":
			c = NewGitHubCollector(cc.LogPath, cc.Tag)
		default:
			m.logger.Warn().Str("type", cc.Type).Msg("unknown collector type, skipping")
			continue
		}

		if err := c.Start(ctx, bus, m.logger); err != nil {
			m.logger.Error().Err(err).Str("collector", c.Name()).Msg("failed to start collector")
			continue
		}

		m.mu.Lock()
		m.collectors = append(m.collectors, c)
		m.mu.Unlock()

		m.logger.Info().Str("collector", c.Name()).Str("path", cc.LogPath).Msg("collector started")
	}
	return nil
}

// StopAll stops all running collectors.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.collectors {
		if err := c.Stop(); err != nil {
			m.logger.Error().Err(err).Str("collector", c.Name()).Msg("error stopping collector")
		}
	}
	m.collectors = nil
}

// Count returns the number of running collectors.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.collectors)
}

// Status returns collector status for the API.
func (m *Manager) Status() []map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]map[string]interface{}, 0, len(m.collectors))
	for _, c := range m.collectors {
		result = append(result, map[string]interface{}{
			"name": c.Name(),
		})
	}
	return result
}

// ---------------------------------------------------------------------------
// tailFile — shared log tailing utility used by all collectors.
// Seeks to end of file and follows new lines. Handles log rotation by
// detecting file truncation or inode change.
// ---------------------------------------------------------------------------

func tailFile(ctx context.Context, path string, handler func(line string), logger zerolog.Logger) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}

	// Seek to end — we only want new lines
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return fmt.Errorf("seeking to end of %s: %w", path, err)
	}

	go func() {
		defer func() { f.Close() }()
		reader := bufio.NewReader(f)
		const maxLineBytes = 1024 * 1024
		var pending []byte
		discarding := false

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			fragment, err := reader.ReadSlice('\n')
			if !discarding {
				if len(pending)+len(fragment) > maxLineBytes {
					logger.Warn().Str("path", path).Msg("oversized log record discarded")
					pending = nil
					discarding = true
				} else {
					pending = append(pending, fragment...)
				}
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				if err == io.EOF {
					// Check for log rotation (file truncated or replaced)
					if info, statErr := os.Stat(path); statErr == nil {
						opened, openedErr := f.Stat()
						offset, seekErr := f.Seek(0, io.SeekCurrent)
						if openedErr == nil && (!os.SameFile(opened, info) || (seekErr == nil && info.Size() < offset)) {
							// File was truncated/rotated — reopen
							logger.Info().Str("path", path).Msg("log rotation detected, reopening")
							newF, openErr := os.Open(path)
							if openErr != nil {
								logger.Error().Err(openErr).Str("path", path).Msg("failed to reopen after rotation")
							} else {
								f.Close()
								f = newF
								reader = bufio.NewReader(f)
								pending = nil
								discarding = false
								continue
							}
						}
					}
					time.Sleep(250 * time.Millisecond)
					continue
				}
				if ctx.Err() != nil {
					return
				}
				logger.Error().Err(err).Str("path", path).Msg("read error")
				time.Sleep(time.Second)
				continue
			}

			if !discarding && len(pending) > 1 {
				handler(string(pending[:len(pending)-1])) // strip trailing newline
			}
			pending = pending[:0]
			discarding = false
		}
	}()

	return nil
}
