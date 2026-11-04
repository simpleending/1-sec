package core

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
)

// Module is the interface that all 1SEC security modules must implement.
type Module interface {
	// Name returns the unique name of the module.
	Name() string
	// Description returns a human-readable description.
	Description() string
	// Start initializes and starts the module.
	Start(ctx context.Context, bus *EventBus, pipeline *AlertPipeline, cfg *Config) error
	// Stop gracefully shuts down the module.
	Stop() error
	// HandleEvent processes an incoming security event.
	HandleEvent(event *SecurityEvent) error
	// EventTypes returns the event types this module handles.
	// The router uses this to avoid dispatching irrelevant events.
	// Return nil or empty to receive all events (backward compat).
	EventTypes() []string
}

// ModuleRegistry manages module registration and lifecycle.
type ModuleRegistry struct {
	mu        sync.RWMutex
	modules   map[string]Module
	order     []string
	logger    zerolog.Logger
	typeIndex map[string][]Module // event type → modules that handle it
	catchAll  []Module            // modules that handle all events (nil EventTypes)
	active    map[string]bool     // nonnil after lifecycle startup; only successful starts route

	// Metrics
	metrics *RegistryMetrics
}

// RegistryMetrics tracks event routing performance.
type RegistryMetrics struct {
	mu                sync.Mutex       `json:"-"`
	EventsRouted      int64            `json:"events_routed"`
	EventsDropped     int64            `json:"events_dropped"`
	EventsByType      map[string]int64 `json:"events_by_type"`
	ModuleErrors      map[string]int64 `json:"module_errors"`
	RoutingSkipped    int64            `json:"routing_skipped"` // events not matching any module
	EventTypeOverflow int64            `json:"event_type_overflow"`
}

// NewModuleRegistry creates a new ModuleRegistry.
func NewModuleRegistry(logger zerolog.Logger) *ModuleRegistry {
	return &ModuleRegistry{
		modules:   make(map[string]Module),
		order:     make([]string, 0),
		logger:    logger.With().Str("component", "module_registry").Logger(),
		typeIndex: make(map[string][]Module),
		catchAll:  make([]Module, 0),
		metrics: &RegistryMetrics{
			EventsByType: make(map[string]int64),
			ModuleErrors: make(map[string]int64),
		},
	}
}

// Register adds a module to the registry.
func (r *ModuleRegistry) Register(mod Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := mod.Name()
	if _, exists := r.modules[name]; exists {
		return fmt.Errorf("module %q already registered", name)
	}

	r.modules[name] = mod
	r.order = append(r.order, name)

	// Build type index for filtered routing
	types := mod.EventTypes()
	if len(types) == 0 {
		r.catchAll = append(r.catchAll, mod)
	} else {
		for _, t := range types {
			r.typeIndex[t] = append(r.typeIndex[t], mod)
		}
	}

	r.logger.Info().Str("module", name).Int("event_types", len(types)).Msg("module registered")
	return nil
}

// RouteEvent dispatches an event only to modules that declared interest in its
// Type. This replaces the O(N) fanout with O(interested) routing.
// Each module dispatch is wrapped in a recover() so a panicking module cannot
// crash the engine.
func (r *ModuleRegistry) RouteEvent(event *SecurityEvent, logger zerolog.Logger) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.metrics.mu.Lock()
	r.metrics.EventsRouted++
	if _, tracked := r.metrics.EventsByType[event.Type]; tracked || len(r.metrics.EventsByType) < 1024 {
		r.metrics.EventsByType[event.Type]++
	} else {
		r.metrics.EventTypeOverflow++
	}
	r.metrics.mu.Unlock()

	routed := false

	// Dispatch to modules that explicitly handle this event type
	if mods, ok := r.typeIndex[event.Type]; ok {
		for _, mod := range mods {
			if r.active != nil && !r.active[mod.Name()] {
				continue
			}
			if mod.Name() == event.Module {
				continue // don't route back to source
			}
			r.safeHandleEvent(mod, event, logger)
			routed = true
		}
	}

	// Dispatch to catch-all modules (those that returned nil/empty EventTypes)
	for _, mod := range r.catchAll {
		if r.active != nil && !r.active[mod.Name()] {
			continue
		}
		if mod.Name() == event.Module {
			continue
		}
		r.safeHandleEvent(mod, event, logger)
		routed = true
	}

	if !routed {
		r.metrics.mu.Lock()
		r.metrics.RoutingSkipped++
		r.metrics.mu.Unlock()
	}
}

// safeHandleEvent calls mod.HandleEvent inside a recover() so a panicking
// module cannot crash the engine. Panics are logged and counted as errors.
func (r *ModuleRegistry) safeHandleEvent(mod Module, event *SecurityEvent, logger zerolog.Logger) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Error().
				Str("module", mod.Name()).
				Str("event_id", event.ID).
				Str("event_type", event.Type).
				Interface("panic", rec).
				Msg("MODULE PANIC — recovered, module did not crash engine")
			r.metrics.mu.Lock()
			r.metrics.ModuleErrors[mod.Name()]++
			r.metrics.mu.Unlock()
		}
	}()

	if err := mod.HandleEvent(event); err != nil {
		logger.Error().Err(err).
			Str("module", mod.Name()).
			Str("event_id", event.ID).
			Str("event_type", event.Type).
			Msg("module failed to handle event")
		r.metrics.mu.Lock()
		r.metrics.ModuleErrors[mod.Name()]++
		r.metrics.mu.Unlock()
	}
}

// GetMetrics returns a snapshot of routing metrics.
func (r *ModuleRegistry) GetMetrics() map[string]interface{} {
	r.metrics.mu.Lock()
	defer r.metrics.mu.Unlock()
	// Copy maps to avoid races
	byType := make(map[string]int64, len(r.metrics.EventsByType))
	for k, v := range r.metrics.EventsByType {
		byType[k] = v
	}
	modErr := make(map[string]int64, len(r.metrics.ModuleErrors))
	for k, v := range r.metrics.ModuleErrors {
		modErr[k] = v
	}
	return map[string]interface{}{
		"events_routed":       r.metrics.EventsRouted,
		"events_dropped":      r.metrics.EventsDropped,
		"events_by_type":      byType,
		"module_errors":       modErr,
		"routing_skipped":     r.metrics.RoutingSkipped,
		"event_type_overflow": r.metrics.EventTypeOverflow,
	}
}

// Get returns a module by name.
func (r *ModuleRegistry) Get(name string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mod, ok := r.modules[name]
	return mod, ok
}

// All returns all registered modules in registration order.
func (r *ModuleRegistry) All() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Module, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, r.modules[name])
	}
	return result
}

// StartAll starts all registered modules that are enabled in config.
func (r *ModuleRegistry) StartAll(ctx context.Context, bus *EventBus, pipeline *AlertPipeline, cfg *Config) error {
	r.mu.Lock()
	r.active = make(map[string]bool)
	r.mu.Unlock()

	for _, mod := range r.All() {
		name := mod.Name()
		if !cfg.IsModuleEnabled(name) {
			r.logger.Info().Str("module", name).Msg("module disabled, skipping")
			continue
		}
		r.logger.Info().Str("module", name).Msg("starting module")
		if err := mod.Start(ctx, bus, pipeline, cfg); err != nil {
			return fmt.Errorf("failed to start module %q: %w", name, err)
		}
		r.mu.Lock()
		r.active[name] = true
		r.mu.Unlock()
		r.logger.Info().Str("module", name).Msg("module started")
	}
	return nil
}

// StopAll stops all registered modules in reverse order.
func (r *ModuleRegistry) StopAll() {
	mods := r.All()
	r.mu.Lock()
	active := r.active
	r.active = make(map[string]bool)
	r.mu.Unlock()
	for i := len(mods) - 1; i >= 0; i-- {
		mod := mods[i]
		name := mod.Name()
		if active != nil && !active[name] {
			continue
		}
		r.logger.Info().Str("module", name).Msg("stopping module")
		if err := mod.Stop(); err != nil {
			r.logger.Error().Err(err).Str("module", name).Msg("error stopping module")
		}
	}
}

// ActiveCount reports modules whose lifecycle startup succeeded.
func (r *ModuleRegistry) ActiveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.active)
}

// Count returns the number of registered modules.
func (r *ModuleRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.modules)
}
