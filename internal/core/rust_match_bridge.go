package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Rust Match Result types — mirrors the Rust MatchResult/PatternMatch structs
// published to sec.matches.> by the Rust sidecar engine.
// ---------------------------------------------------------------------------

// RustMatchResult is the Go representation of the Rust engine's MatchResult.
type RustMatchResult struct {
	Context          map[string]string  `json:"context,omitempty"`
	EventID          string             `json:"event_id"`
	Timestamp        time.Time          `json:"timestamp"`
	Matches          []RustPatternMatch `json:"matches"`
	AggregateScore   float64            `json:"aggregate_score"`
	HighestSeverity  string             `json:"highest_severity"`
	ProcessingTimeUs uint64             `json:"processing_time_us"`
}

// RustPatternMatch is a single pattern match from the Rust engine.
type RustPatternMatch struct {
	PatternName string `json:"pattern_name"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	MatchedText string `json:"matched_text"`
	Field       string `json:"field"`
	Offset      int    `json:"offset"`
}

// ---------------------------------------------------------------------------
// RustMatchBridge — converts Rust match results into alerts for enforcement.
//
// Design decisions informed by best practices:
// - Deduplication: tracks recently seen event IDs to avoid double-enforcement
//   when both Go and Rust detect the same threat on the same event.
// - Enrichment: carries pattern match details into alert metadata so the
//   ResponseEngine has full context for enforcement decisions.
// - Severity mapping: maps Rust severity strings to Go Severity iota values.
// ---------------------------------------------------------------------------

// RustMatchBridge subscribes to Rust sidecar match results and converts them
// into alerts that feed the enforcement pipeline.
type RustMatchBridge struct {
	logger   zerolog.Logger
	pipeline *AlertPipeline
	bus      *EventBus

	// Deduplication: track event IDs we've already generated alerts for
	// from duplicate sidecar deliveries.
	seen   map[string]time.Time
	seenMu sync.Mutex
}

// NewRustMatchBridge creates a new bridge between Rust match results and the
// Go alert/enforcement pipeline.
func NewRustMatchBridge(logger zerolog.Logger, pipeline *AlertPipeline, bus *EventBus) *RustMatchBridge {
	return &RustMatchBridge{
		logger:   logger.With().Str("component", "rust_match_bridge").Logger(),
		pipeline: pipeline,
		bus:      bus,
		seen:     make(map[string]time.Time),
	}
}

// Start subscribes to sec.matches.> and begins converting Rust match results
// into alerts. Call after the EventBus is ready.
func (b *RustMatchBridge) Start(ctx context.Context) error {
	err := b.bus.SubscribeToRustMatches(func(data []byte) {
		b.handleMatchResult(data)
	})
	if err != nil {
		return fmt.Errorf("subscribing to rust match results: %w", err)
	}

	// Periodic cleanup of the dedup map
	go b.cleanupLoop(ctx)

	b.logger.Info().Msg("rust match bridge started — enforcement will process Rust sidecar detections")
	return nil
}

func (b *RustMatchBridge) handleMatchResult(data []byte) {
	var result RustMatchResult
	if err := json.Unmarshal(data, &result); err != nil {
		b.logger.Error().Err(err).Msg("failed to unmarshal rust match result")
		return
	}

	if len(result.Matches) == 0 {
		return
	}

	// Dedup repeated sidecar results without suppressing independent Go analysis.
	b.seenMu.Lock()
	if _, exists := b.seen[result.EventID]; exists {
		b.seenMu.Unlock()
		b.logger.Debug().
			Str("event_id", result.EventID).
			Int("rust_matches", len(result.Matches)).
			Msg("skipping duplicate rust match")
		return
	}
	b.seen[result.EventID] = time.Now()
	b.seenMu.Unlock()

	// Map Rust severity string to Go Severity
	severity := mapRustSeverity(result.HighestSeverity)

	// Build a descriptive title from the match categories
	categories := uniqueCategories(result.Matches)
	title := fmt.Sprintf("Rust engine detected: %s", strings.Join(categories, ", "))

	// Build description with pattern details
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("Rust sidecar matched %d pattern(s) on event %s (score: %.2f, %dμs).\n",
		len(result.Matches), result.EventID, result.AggregateScore, result.ProcessingTimeUs))
	for i, m := range result.Matches {
		if i >= 5 {
			desc.WriteString(fmt.Sprintf("... and %d more\n", len(result.Matches)-5))
			break
		}
		desc.WriteString(fmt.Sprintf("  - [%s] %s in field %q\n", m.Severity, m.PatternName, m.Field))
	}

	alert := &Alert{
		ID:          uuid.New().String(),
		Timestamp:   result.Timestamp,
		Module:      inferModule(result.Matches),
		Type:        "rust_pattern_match",
		Severity:    severity,
		Status:      AlertStatusOpen,
		Title:       title,
		Description: desc.String(),
		EventIDs:    []string{result.EventID},
		Metadata: map[string]interface{}{
			"source":          "rust_sidecar",
			"aggregate_score": result.AggregateScore,
			"match_count":     len(result.Matches),
			"categories":      categories,
			"processing_us":   result.ProcessingTimeUs,
			"pattern_matches": result.Matches,
		},
	}

	if ip := net.ParseIP(result.Context["source_ip"]); ip != nil {
		alert.Metadata["source_ip"] = ip.String()
	}
	for _, key := range []string{"user_id", "account_id", "session_id"} {
		if value := result.Context[key]; value != "" && len(value) <= 256 {
			alert.Metadata[key] = value
		}
	}
	b.pipeline.Process(alert)

	b.logger.Info().
		Str("alert_id", alert.ID).
		Str("event_id", result.EventID).
		Int("matches", len(result.Matches)).
		Str("severity", severity.String()).
		Float64("score", result.AggregateScore).
		Msg("rust match converted to alert for enforcement")
}

func (b *RustMatchBridge) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.seenMu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for id, ts := range b.seen {
				if ts.Before(cutoff) {
					delete(b.seen, id)
				}
			}
			b.seenMu.Unlock()
		}
	}
}

// mapRustSeverity converts the Rust severity string (lowercase) to Go Severity.
func mapRustSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// inferModule maps Rust pattern categories back to the most relevant Go module
// name so enforcement policies can match correctly.
func inferModule(matches []RustPatternMatch) string {
	categoryToModule := map[string]string{
		"sqli":               "injection_shield",
		"xss":                "injection_shield",
		"cmdi":               "injection_shield",
		"ldapi":              "injection_shield",
		"nosql_injection":    "injection_shield",
		"template_injection": "injection_shield",
		"path_traversal":     "injection_shield",
		"deserialization":    "injection_shield",
		"ssrf":               "network_guardian",
		"data_exfiltration":  "network_guardian",
		"ransomware":         "ransomware",
		"auth_bypass":        "auth_fortress",
		"credential_attack":  "auth_fortress",
		"prompt_injection":   "llm_firewall",
		"canary_token":       "supply_chain",
		// Agentic web access categories (2026)
		"markdown_injection":    "ai_containment",
		"agent_web_recon":       "ai_containment",
		"agent_payment_fraud":   "ai_containment",
		"x402_abuse":            "ai_containment",
		"llms_txt_poisoning":    "data_poisoning",
		"web_content_tampering": "data_poisoning",
		"agent_delegation":      "ai_containment",
	}

	// Use the highest-severity match's category to pick the module
	bestModule := "rust_engine"
	bestSev := SeverityInfo
	for _, m := range matches {
		sev := mapRustSeverity(m.Severity)
		if sev > bestSev {
			bestSev = sev
			if mod, ok := categoryToModule[m.Category]; ok {
				bestModule = mod
			}
		}
	}
	return bestModule
}

// uniqueCategories returns deduplicated category names from matches.
func uniqueCategories(matches []RustPatternMatch) []string {
	seen := make(map[string]bool)
	var cats []string
	for _, m := range matches {
		if !seen[m.Category] {
			seen[m.Category] = true
			cats = append(cats, m.Category)
		}
	}
	return cats
}
