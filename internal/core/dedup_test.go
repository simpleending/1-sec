package core

import (
	"fmt"
	"testing"
	"time"
)

func TestEventDedup_NewEvent_NotDuplicate(t *testing.T) {
	d := NewEventDedup(5*time.Second, 1000)
	e := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_failure", SourceIP: "1.2.3.4", Summary: "test"}
	if d.IsDuplicate(e) {
		t.Error("first event should not be a duplicate")
	}
}

func TestEventDedup_SameEvent_IsDuplicate(t *testing.T) {
	d := NewEventDedup(5*time.Second, 1000)
	e := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_failure", SourceIP: "1.2.3.4", Summary: "test"}
	d.IsDuplicate(e)
	if !d.IsDuplicate(e) {
		t.Error("identical event should be a duplicate")
	}
}

func TestEventDedup_DifferentType_NotDuplicate(t *testing.T) {
	d := NewEventDedup(5*time.Second, 1000)
	e1 := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_failure", SourceIP: "1.2.3.4", Summary: "test"}
	e2 := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_success", SourceIP: "1.2.3.4", Summary: "test"}
	d.IsDuplicate(e1)
	if d.IsDuplicate(e2) {
		t.Error("different event type should not be a duplicate")
	}
}

func TestEventDedup_DifferentIP_NotDuplicate(t *testing.T) {
	d := NewEventDedup(5*time.Second, 1000)
	e1 := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_failure", SourceIP: "1.2.3.4", Summary: "test"}
	e2 := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_failure", SourceIP: "5.6.7.8", Summary: "test"}
	d.IsDuplicate(e1)
	if d.IsDuplicate(e2) {
		t.Error("different source IP should not be a duplicate")
	}
}

func TestEventDedup_DifferentSummary_NotDuplicate(t *testing.T) {
	d := NewEventDedup(5*time.Second, 1000)
	e1 := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_failure", SourceIP: "1.2.3.4", Summary: "brute force"}
	e2 := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_failure", SourceIP: "1.2.3.4", Summary: "credential stuffing"}
	d.IsDuplicate(e1)
	if d.IsDuplicate(e2) {
		t.Error("different summary should not be a duplicate")
	}
}

func TestEventDedup_TTLExpiry(t *testing.T) {
	d := NewEventDedup(50*time.Millisecond, 1000)
	e := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "login_failure", SourceIP: "1.2.3.4", Summary: "test"}
	d.IsDuplicate(e)
	time.Sleep(100 * time.Millisecond)
	if d.IsDuplicate(e) {
		t.Error("event should not be duplicate after TTL expiry")
	}
}

func TestEventDedup_MaxSizeEviction(t *testing.T) {
	d := NewEventDedup(10*time.Second, 10)
	// Fill beyond capacity
	for i := 0; i < 20; i++ {
		e := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: fmt.Sprintf("type_%d", i), SourceIP: "1.2.3.4", Summary: "test"}
		d.IsDuplicate(e)
	}
	// Size should be capped
	if d.Size() > 15 { // some slack for eviction timing
		t.Errorf("cache size %d exceeds expected cap", d.Size())
	}
}

func TestEventDedup_RawDataIncludedInHash(t *testing.T) {
	d := NewEventDedup(5*time.Second, 1000)
	e1 := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "syslog", SourceIP: "1.2.3.4", Summary: "test", RawData: []byte("line A")}
	e2 := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "syslog", SourceIP: "1.2.3.4", Summary: "test", RawData: []byte("line B")}
	d.IsDuplicate(e1)
	if d.IsDuplicate(e2) {
		t.Error("different raw data should produce different hashes")
	}
}

func TestEventDedup_StartCleanup(t *testing.T) {
	d := NewEventDedup(50*time.Millisecond, 1000)
	e := &SecurityEvent{Timestamp: time.Unix(1, 0), Type: "test", SourceIP: "1.2.3.4", Summary: "test"}
	d.IsDuplicate(e)
	if d.Size() != 1 {
		t.Fatalf("expected size 1, got %d", d.Size())
	}

	stop := d.StartCleanup(50 * time.Millisecond)
	defer stop()

	time.Sleep(200 * time.Millisecond)
	if d.Size() != 0 {
		t.Errorf("expected size 0 after cleanup, got %d", d.Size())
	}
}

func TestEventDedup_Size(t *testing.T) {
	d := NewEventDedup(5*time.Second, 1000)
	if d.Size() != 0 {
		t.Errorf("expected size 0, got %d", d.Size())
	}
	d.IsDuplicate(&SecurityEvent{Timestamp: time.Unix(1, 0), Type: "a", SourceIP: "1.1.1.1"})
	d.IsDuplicate(&SecurityEvent{Timestamp: time.Unix(1, 0), Type: "b", SourceIP: "2.2.2.2"})
	if d.Size() != 2 {
		t.Errorf("expected size 2, got %d", d.Size())
	}
}
