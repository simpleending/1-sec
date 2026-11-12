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
func (m *Manager) StartAll(ctx context.Context, cfg core.CollectorsConfig, bus *core.EventBus) error {
	if err := cfg.Validate(); err != nil || !cfg.Enabled {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	first := len(m.collectors)
	for _, cc := range cfg.Sources {
		var c Collector
		switch cc.Type {
		case "nginx":
			c = NewNginxCollector(cc.LogPath, cc.Tag)
		case "auth", "authlog":
			c = NewAuthLogCollector(cc.LogPath, cc.Tag)
		case "pfsense":
			c = NewPfSenseCollector(cc.LogPath, cc.Tag)
		case "json", "jsonlog":
			c = NewJSONLogCollector(cc.LogPath, cc.Tag)
		case "github":
			c = NewGitHubCollector(cc.LogPath, cc.Tag)
		}

		if err := c.Start(ctx, bus, m.logger); err != nil {
			m.stopFrom(first)
			return fmt.Errorf("starting %s: %w", c.Name(), err)
		}

		m.collectors = append(m.collectors, c)

		m.logger.Info().Str("collector", c.Name()).Str("path", cc.LogPath).Msg("collector started")
	}
	return nil
}

// StopAll stops all running collectors.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopFrom(0)
}

func (m *Manager) stopFrom(first int) {
	for _, c := range m.collectors[first:] {
		if err := c.Stop(); err != nil {
			m.logger.Error().Err(err).Str("collector", c.Name()).Msg("error stopping collector")
		}
	}
	clear(m.collectors[first:])
	m.collectors = m.collectors[:first]
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

func tailFile(parent context.Context, path string, handler func(line string), logger zerolog.Logger) (stop func(), err error) {
	f, err := openLogFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	// Seek to end — we only want new lines
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, fmt.Errorf("seeking to end of %s: %w", path, err)
	}

	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
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
							newF, openErr := openLogFile(path)
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
					select {
					case <-ctx.Done():
						return
					case <-time.After(250 * time.Millisecond):
					}
					continue
				}
				if ctx.Err() != nil {
					return
				}
				logger.Error().Err(err).Str("path", path).Msg("read error")
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				continue
			}

			if !discarding && len(pending) > 1 {
				handler(string(pending[:len(pending)-1])) // strip trailing newline
			}
			pending = pending[:0]
			discarding = false
		}
	}()

	return func() {
		cancel()
		<-done
	}, nil
}

func openLogFile(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("expected a regular log file")
	}
	return os.Open(path)
}

func publishCollectedEvent(bus *core.EventBus, event *core.SecurityEvent, logger zerolog.Logger) {
	if err := bus.PublishEvent(event); err != nil {
		logger.Error().Err(err).Str("type", event.Type).Msg("failed to publish collector event")
	}
}
