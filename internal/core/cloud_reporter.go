package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// CloudReporter sends enforcement records, correlations, and heartbeats
// to the 1SEC cloud dashboard via POST /api/v1/ingest.
type CloudReporter struct {
	cfg    *Config
	engine *Engine
	logger zerolog.Logger
	ctx    context.Context
	cancel context.CancelFunc
}

// CloudEnforcementRecord is the shape expected by the cloud dashboard's ingest API.
type CloudEnforcementRecord struct {
	ID               string `json:"id"`
	Timestamp        string `json:"timestamp"`
	Module           string `json:"module"`
	Action           string `json:"action"`
	Target           string `json:"target"`
	Severity         string `json:"severity"`
	AlertID          string `json:"alertId"`
	Status           string `json:"status"`
	DurationMs       int64  `json:"durationMs,omitempty"`
	DryRun           bool   `json:"dryRun"`
	Preset           string `json:"preset,omitempty"`
	Details          string `json:"details,omitempty"`
	Error            string `json:"error,omitempty"`
	Reversible       bool   `json:"reversible,omitempty"`
	RolledBack       bool   `json:"rolledBack,omitempty"`
	ApprovalID       string `json:"approvalId,omitempty"`
	ApprovalRequired bool   `json:"approvalRequired,omitempty"`
	ApprovalStatus   string `json:"approvalStatus,omitempty"`
	MitreTactic      string `json:"mitreTactic,omitempty"`
	MitreTechnique   string `json:"mitreTechnique,omitempty"`
	InstanceID       string `json:"instanceId,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
}

// CloudCorrelationRecord is the shape expected by the cloud dashboard's ingest API.
type CloudCorrelationRecord struct {
	ID              string   `json:"id"`
	Timestamp       string   `json:"timestamp"`
	ChainName       string   `json:"chainName"`
	SourceIP        string   `json:"sourceIp"`
	Modules         []string `json:"modules"`
	AlertIDs        []string `json:"alertIds"`
	Severity        string   `json:"severity"`
	Summary         string   `json:"summary"`
	WindowSeconds   int      `json:"windowSeconds"`
	IncidentStatus  string   `json:"incidentStatus,omitempty"`
	MitreTactics    []string `json:"mitreTactics,omitempty"`
	MitreTechniques []string `json:"mitreTechniques,omitempty"`
}

// CloudHeartbeat is the shape expected by the cloud dashboard's ingest API.
type CloudHeartbeat struct {
	InstanceID        string   `json:"instanceId"`
	Hostname          string   `json:"hostname"`
	Version           string   `json:"version"`
	Uptime            int64    `json:"uptime"`
	Timestamp         string   `json:"timestamp"`
	ModulesActive     int      `json:"modulesActive"`
	ModulesTotal      int      `json:"modulesTotal"`
	BusConnected      bool     `json:"busConnected"`
	RustEngine        bool     `json:"rustEngine"`
	ArchiveEnabled    bool     `json:"archiveEnabled"`
	CollectorsRunning []string `json:"collectorsRunning"`
	AlertCount        int      `json:"alertCount"`
	EventsProcessed   int64    `json:"eventsProcessed"`
	EnforcementMode   string   `json:"enforcementMode"`
	Preset            string   `json:"preset,omitempty"`
	DisabledModules   []string `json:"disabledModules,omitempty"`
}

// NewCloudReporter creates a new cloud reporter.
func NewCloudReporter(engine *Engine) *CloudReporter {
	ctx, cancel := context.WithCancel(context.Background())
	cr := &CloudReporter{
		cfg:    engine.Config,
		engine: engine,
		logger: engine.Logger.With().Str("component", "cloud_reporter").Logger(),
		ctx:    ctx,
		cancel: cancel,
	}

	// Hook into the alert pipeline to capture correlation alerts for cloud reporting
	engine.Pipeline.AddHandler(func(alert *Alert) {
		if chainName, ok := alert.Metadata["chain_name"].(string); ok && chainName != "" {
			go cr.reportCorrelation(alert, chainName)
		}
	})

	return cr
}

// Start begins the heartbeat loop and enforcement/correlation reporting.
func (cr *CloudReporter) Start() {
	if !cr.cfg.Cloud.Enabled || cr.cfg.Cloud.APIKey == "" {
		cr.logger.Info().Msg("cloud reporting disabled (no API key configured)")
		return
	}

	interval := cr.cfg.Cloud.HeartbeatInterval
	if interval <= 0 {
		interval = 60
	}

	cr.logger.Info().
		Str("url", cr.cfg.Cloud.APIURL).
		Int("heartbeat_interval", interval).
		Msg("cloud reporting started")

	go cr.heartbeatLoop(time.Duration(interval) * time.Second)
	go cr.enforcementReporter()
}

// Stop terminates the cloud reporter.
func (cr *CloudReporter) Stop() {
	if cr.cancel != nil {
		cr.cancel()
	}
}

func (cr *CloudReporter) heartbeatLoop(interval time.Duration) {
	// Send initial heartbeat after a short delay to let modules start
	time.Sleep(5 * time.Second)
	cr.sendHeartbeat()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-cr.ctx.Done():
			return
		case <-ticker.C:
			cr.sendHeartbeat()
		}
	}
}

func (cr *CloudReporter) sendHeartbeat() {
	hostname, _ := os.Hostname()

	// Count active/disabled modules
	modulesActive := 0
	modulesTotal := 0
	var disabledModules []string
	for name, modCfg := range cr.cfg.Modules {
		modulesTotal++
		if modCfg.Enabled {
			modulesActive++
		} else {
			disabledModules = append(disabledModules, name)
		}
	}

	enforcementMode := "disabled"
	preset := ""
	if cr.cfg.Enforcement != nil && cr.cfg.Enforcement.Enabled {
		if cr.cfg.Enforcement.GetDryRun() {
			enforcementMode = "dry_run"
		} else {
			enforcementMode = "active"
		}
		preset = cr.cfg.Enforcement.Preset
	}

	rustEngine := cr.cfg.RustEngine.Enabled && cr.engine.RustSidecar != nil && cr.engine.RustSidecar.Running()

	hb := CloudHeartbeat{
		InstanceID:        fmt.Sprintf("i-%s-%s", hostname, runtime.GOARCH),
		Hostname:          hostname,
		Version:           Version,
		Uptime:            int64(time.Since(cr.engine.startTime).Seconds()),
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		ModulesActive:     modulesActive,
		ModulesTotal:      modulesTotal,
		BusConnected:      cr.engine.Bus != nil && cr.engine.Bus.IsConnected(),
		RustEngine:        rustEngine,
		ArchiveEnabled:    cr.cfg.Archive.Enabled,
		CollectorsRunning: []string{},
		AlertCount:        cr.engine.Pipeline.Count(),
		EventsProcessed:   cr.engine.Bus.GetMetrics()["events_published"],
		EnforcementMode:   enforcementMode,
		Preset:            preset,
		DisabledModules:   disabledModules,
	}

	payload := map[string]interface{}{
		"type":      "heartbeat",
		"heartbeat": hb,
	}

	if err := cr.postIngest(payload); err != nil {
		cr.logger.Debug().Err(err).Msg("heartbeat send failed")
	}
}

// enforcementReporter periodically sends new enforcement records to the cloud.
func (cr *CloudReporter) enforcementReporter() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	sent := make(map[string]bool)

	for {
		select {
		case <-cr.ctx.Done():
			return
		case <-ticker.C:
			if cr.engine.ResponseEngine == nil {
				continue
			}

			records := cr.engine.ResponseEngine.GetRecords(100, "")
			newRecords := make([]*ResponseRecord, 0, len(records))
			for _, r := range records {
				if sent[r.ID] {
					continue
				}
				newRecords = append(newRecords, r)
			}
			if len(newRecords) == 0 {
				continue
			}

			hostname, _ := os.Hostname()
			instanceID := fmt.Sprintf("i-%s-%s", hostname, runtime.GOARCH)

			cloudRecords := make([]CloudEnforcementRecord, 0, len(newRecords))
			for _, r := range newRecords {
				// Use actual severity from the enforcement record instead of hardcoded value
				severity := strings.ToLower(r.Severity)
				if severity == "" {
					severity = "medium"
				}
				// Map Go-side uppercase status to dashboard lowercase.
				status := strings.ToLower(string(r.Status))
				dryRun := r.Status == ActionStatusDryRun
				approvalID := ""
				approvalRequired := false
				approvalStatus := ""
				if r.Status == ActionStatusSkipped && strings.HasPrefix(r.Details, "held for approval:") {
					approvalID = strings.TrimSpace(strings.TrimPrefix(r.Details, "held for approval:"))
					approvalRequired = true
					approvalStatus = "pending"
					status = "allowed"
				}
				cloudRecords = append(cloudRecords, CloudEnforcementRecord{
					ID:               r.ID,
					Timestamp:        r.Timestamp.Format(time.RFC3339),
					Module:           r.Module,
					Action:           string(r.Action),
					Target:           r.Target,
					Severity:         severity,
					AlertID:          r.AlertID,
					Status:           status,
					DurationMs:       r.DurationMs,
					DryRun:           dryRun,
					Details:          r.Details,
					Error:            r.Error,
					ApprovalID:       approvalID,
					ApprovalRequired: approvalRequired,
					ApprovalStatus:   approvalStatus,
					InstanceID:       instanceID,
					Hostname:         hostname,
				})
			}

			payload := map[string]interface{}{
				"type":    "enforcement",
				"records": cloudRecords,
			}

			if err := cr.postIngest(payload); err != nil {
				cr.logger.Debug().Err(err).Msg("enforcement report failed")
				continue
			}
			for _, r := range newRecords {
				sent[r.ID] = true
			}
		}
	}
}

func (cr *CloudReporter) reportCorrelation(alert *Alert, chainName string) {
	modules, _ := alert.Metadata["modules"].([]string)
	sourceIP, _ := alert.Metadata["source_ip"].(string)

	rec := CloudCorrelationRecord{
		ID:             alert.ID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		ChainName:      chainName,
		SourceIP:       sourceIP,
		Modules:        modules,
		AlertIDs:       alert.EventIDs,
		Severity:       strings.ToLower(alert.Severity.String()),
		Summary:        alert.Description,
		WindowSeconds:  900, // 15 min default
		IncidentStatus: "new",
	}

	payload := map[string]interface{}{
		"type":         "correlation",
		"correlations": []CloudCorrelationRecord{rec},
	}

	if err := cr.postIngest(payload); err != nil {
		cr.logger.Debug().Err(err).Msg("correlation report failed")
	}
}

func (cr *CloudReporter) postIngest(payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	url := strings.TrimRight(cr.cfg.Cloud.APIURL, "/") + "/ingest"
	req, err := newAuthRequest("POST", url, body, cr.cfg.Cloud.APIKey)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("cloud API returned %d", resp.StatusCode)
	}

	return nil
}
