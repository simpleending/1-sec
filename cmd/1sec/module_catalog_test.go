package main

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

func TestModuleCatalogMatchesRuntime(t *testing.T) {
	modules := builtinModules()
	if len(allModules) != 16 || len(modules) != len(allModules) {
		t.Fatal("CLI must expose all 16 built-in modules")
	}
	seen := make(map[string]bool)
	for _, info := range allModules {
		if seen[info.Name] {
			t.Fatalf("duplicate module %s", info.Name)
		}
		seen[info.Name] = true
		found := false
		for _, module := range modules {
			if module.Name() != info.Name {
				continue
			}
			found = true
			events := module.EventTypes()
			if len(events) == 0 {
				events = []string{"*"}
			}
			if info.Description != module.Description() || !slices.Equal(info.EventTypes, events) {
				t.Errorf("CLI integration contract differs from runtime for %s", info.Name)
			}
		}
		if !found {
			t.Errorf("CLI advertises nonexistent module %s", info.Name)
		}
	}
}

// Exercise the real dispatch index as well as the handlers. Direct handler unit
// tests alone cannot detect an alias missing from the registry subscription.
func TestRuntimeRoutesDocumentedDetectionAliases(t *testing.T) {
	registry := core.NewModuleRegistry(zerolog.Nop())
	for _, module := range builtinModules() {
		if module.Name() == "ai_containment" || module.Name() == "data_poisoning" {
			if err := registry.Register(module); err != nil {
				t.Fatal(err)
			}
		}
	}
	pipeline := core.NewAlertPipeline(zerolog.Nop(), 100)
	var mu sync.Mutex
	found := make(map[string]bool)
	pipeline.AddHandler(func(alert *core.Alert) {
		mu.Lock()
		defer mu.Unlock()
		found[alert.Type] = true
	})
	if err := registry.StartAll(context.Background(), nil, pipeline, core.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.StopAll)
	connection := core.NewSecurityEvent("test", "network_connection", core.SeverityInfo, "connection")
	connection.Details["dest_host"] = "api.openai.com"
	registry.RouteEvent(connection, zerolog.Nop())
	prediction := core.NewSecurityEvent("test", "inference_result", core.SeverityInfo, "prediction")
	prediction.Details["model_id"] = "test-model"
	prediction.Details["confidence"] = 0.05
	registry.RouteEvent(prediction, zerolog.Nop())
	mu.Lock()
	defer mu.Unlock()
	for _, alertType := range []string{"shadow_ai_detected", "adversarial_input"} {
		if !found[alertType] {
			t.Errorf("registry did not deliver the event needed for %s", alertType)
		}
	}
}
