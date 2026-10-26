package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// EventDedup is a short-lived deduplication cache that prevents the same event
// from being processed twice. Fingerprints preserve observation identity and
// all detector input so independent repeated activity still reaches rate detectors.
type EventDedup struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	ttl     time.Duration
	maxSize int
}

// NewEventDedup creates a dedup cache. TTL controls how long a hash is
// remembered. maxSize caps memory usage by evicting oldest entries.
func NewEventDedup(ttl time.Duration, maxSize int) *EventDedup {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if maxSize <= 0 {
		maxSize = 50000
	}
	d := &EventDedup{
		seen:    make(map[string]time.Time, maxSize/2),
		ttl:     ttl,
		maxSize: maxSize,
	}
	return d
}

// IsDuplicate returns true if this event was seen within the TTL window.
// If not a duplicate, it records the event hash.
func (d *EventDedup) IsDuplicate(event *SecurityEvent) bool {
	// Without observation identity, equal content cannot establish a replay.
	if event.ID == "" && event.Timestamp.IsZero() {
		return false
	}
	hash, err := d.hash(event)
	if err != nil {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Check if seen and still within TTL
	if seenAt, ok := d.seen[hash]; ok {
		if now.Sub(seenAt) < d.ttl {
			return true
		}
	}

	// Record and evict if over capacity
	d.seen[hash] = now
	if len(d.seen) > d.maxSize {
		d.evictLocked(now)
	}

	return false
}

// hash keeps structured values and full content, with canonical JSON map ordering.
func (d *EventDedup) hash(event *SecurityEvent) (string, error) {
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(event); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}

// evictLocked removes entries older than TTL. Called when cache exceeds maxSize.
func (d *EventDedup) evictLocked(now time.Time) {
	for k, t := range d.seen {
		if now.Sub(t) >= d.ttl {
			delete(d.seen, k)
		}
	}
	// If still over capacity after TTL eviction, drop oldest half
	if len(d.seen) > d.maxSize {
		count := 0
		target := len(d.seen) / 2
		for k := range d.seen {
			delete(d.seen, k)
			count++
			if count >= target {
				break
			}
		}
	}
}

// StartCleanup runs a background goroutine that periodically evicts expired
// entries. Call the returned function to stop it.
func (d *EventDedup) StartCleanup(interval time.Duration) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				d.mu.Lock()
				now := time.Now()
				for k, t := range d.seen {
					if now.Sub(t) >= d.ttl {
						delete(d.seen, k)
					}
				}
				d.mu.Unlock()
			}
		}
	}()
	return func() { close(done) }
}

// Size returns the current number of entries in the cache.
func (d *EventDedup) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
