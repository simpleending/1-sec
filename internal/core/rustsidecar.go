package core

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// RustSidecar manages the lifecycle of the optional Rust engine process.
// It auto-starts the Rust binary as a subprocess, monitors its health,
// and restarts it on crash with exponential backoff.
type RustSidecar struct {
	cfg    *RustEngineConfig
	busCfg *BusConfig
	logger zerolog.Logger

	cmd    *exec.Cmd
	cancel context.CancelFunc
	mu     sync.Mutex

	// Restart backoff
	restartCount int
	maxRestarts  int
}

// NewRustSidecar creates a new Rust sidecar manager.
func NewRustSidecar(cfg *RustEngineConfig, busCfg *BusConfig, logger zerolog.Logger) *RustSidecar {
	return &RustSidecar{
		cfg:         cfg,
		busCfg:      busCfg,
		logger:      logger.With().Str("component", "rust_sidecar").Logger(),
		maxRestarts: 10,
	}
}

// Start launches the Rust engine process.
func (rs *RustSidecar) Start(parentCtx context.Context, configPath string) error {
	if !rs.cfg.Enabled {
		rs.logger.Debug().Msg("rust engine disabled, skipping")
		return nil
	}

	binary, err := rs.findBinary()
	if err != nil {
		rs.logger.Warn().Err(err).Msg("rust engine binary not found — running without it")
		return nil // Non-fatal: the Go engine works fine without Rust
	}

	ctx, cancel := context.WithCancel(parentCtx)
	rs.cancel = cancel

	go rs.supervise(ctx, binary, configPath)

	return nil
}

// Stop terminates the Rust engine process.
func (rs *RustSidecar) Stop() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.cancel != nil {
		rs.cancel()
	}

	if rs.cmd != nil && rs.cmd.Process != nil {
		rs.logger.Info().Msg("stopping rust engine")
		// Send SIGTERM for graceful shutdown
		_ = rs.cmd.Process.Signal(os.Interrupt)

		// Wait up to 5 seconds for graceful exit
		done := make(chan error, 1)
		go func() { done <- rs.cmd.Wait() }()

		select {
		case <-done:
			rs.logger.Info().Msg("rust engine stopped gracefully")
		case <-time.After(5 * time.Second):
			rs.logger.Warn().Msg("rust engine did not stop in time, killing")
			_ = rs.cmd.Process.Kill()
		}
	}
}

// Running returns true if the Rust engine process is currently running.
func (rs *RustSidecar) Running() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.cmd != nil && rs.cmd.Process != nil && rs.cmd.ProcessState == nil
}

// supervise runs the Rust engine and restarts it on crash with backoff.
func (rs *RustSidecar) supervise(ctx context.Context, binary, configPath string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if rs.restartCount >= rs.maxRestarts {
			rs.logger.Error().
				Int("restarts", rs.restartCount).
				Msg("rust engine exceeded max restarts, giving up")
			return
		}

		args := rs.buildArgs(configPath)
		rs.logger.Info().
			Str("binary", binary).
			Strs("args", args).
			Int("restart", rs.restartCount).
			Msg("starting rust engine")

		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		rs.mu.Lock()
		rs.cmd = cmd
		rs.mu.Unlock()

		err := cmd.Run()

		if ctx.Err() != nil {
			// Context cancelled — intentional shutdown
			return
		}

		if err != nil {
			rs.restartCount++
			backoff := time.Duration(rs.restartCount*rs.restartCount) * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			// Add jitter (±25%) to prevent thundering herd on multi-instance deployments
			// #nosec G404 -- retry timing is not a security-sensitive random value.
			jitter := time.Duration(rand.Int63n(int64(backoff/4)+1)) - backoff/8
			backoff += jitter
			rs.logger.Warn().
				Err(err).
				Int("restart", rs.restartCount).
				Dur("backoff", backoff).
				Msg("rust engine exited, restarting after backoff")

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		} else {
			// Clean exit — don't restart
			rs.logger.Info().Msg("rust engine exited cleanly")
			return
		}
	}
}

// buildArgs constructs the CLI arguments for the Rust engine binary.
func (rs *RustSidecar) buildArgs(configPath string) []string {
	natsURL := rs.busCfg.URL
	if rs.busCfg.Embedded {
		natsURL = fmt.Sprintf("nats://127.0.0.1:%d", rs.busCfg.Port)
	}

	args := []string{
		"--config", configPath,
		"--nats-url", natsURL,
		"--log-format", "json",
		"--log-level", "info",
	}

	if rs.cfg.Capture.Enabled {
		args = append(args, "--capture", "--interface", rs.cfg.Capture.Interface)
	}

	return args
}

// findBinary locates the Rust engine binary.
func (rs *RustSidecar) findBinary() (string, error) {
	binary := rs.cfg.Binary
	if binary == "" {
		binary = "1sec-engine"
	}

	// If it's an absolute path, check it directly
	if filepath.IsAbs(binary) {
		if _, err := os.Stat(binary); err != nil {
			return "", fmt.Errorf("rust engine binary not found at %s: %w", binary, err)
		}
		return binary, nil
	}

	// Check common locations relative to the main binary
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)

	candidates := []string{
		filepath.Join(execDir, binary),
		filepath.Join(".", binary),
		filepath.Join(".", "rust", "1sec-engine", "target", "release", binary),
	}

	// Add platform-specific extension on Windows
	if runtime.GOOS == "windows" {
		for i, c := range candidates {
			if filepath.Ext(c) == "" {
				candidates[i] = c + ".exe"
			}
		}
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			abs, _ := filepath.Abs(candidate)
			return abs, nil
		}
	}

	// Fall back to PATH lookup
	path, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("rust engine binary %q not found in PATH or common locations", binary)
	}
	return path, nil
}
