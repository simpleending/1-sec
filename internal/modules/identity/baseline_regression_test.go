package identity

import (
	"testing"
	"time"
)

func TestContinuousServiceAccountBaselineIsIndependentOfHourlyCounter(t *testing.T) {
	m := NewServiceAccountMonitor()
	m.RecordAndAnalyze("svc", "read", "db", "192.0.2.1")
	p := m.accounts["svc"]
	p.BaselineStart = time.Now().Add(-25 * time.Hour)
	p.CountWindow = time.Now().Add(-2 * time.Hour)
	if a := m.RecordAndAnalyze("svc", "read", "db", "192.0.2.1"); a.UnusualAction || a.UnusualIP {
		t.Fatal("known behavior changed")
	}
	for i := 0; i < 2; i++ {
		a := m.RecordAndAnalyze("svc", "delete", "db", "192.0.2.2")
		if !a.UnusualAction || !a.UnusualIP {
			t.Fatal("new behavior silently learned after baseline")
		}
	}
}
