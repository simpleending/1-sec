package datapoisoning

import (
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
)

func TestGuard_WebContentDomainBaselineAndMutation(t *testing.T) {
	cp := makeCapturingPipeline()
	g := startedModuleWithPipeline(t, cp)
	defer g.Stop()
	report := func(path, hash string) {
		t.Helper()
		e := core.NewSecurityEvent("test", "llms_txt_fetch", core.SeverityInfo, "inert metadata fixture")
		e.Details = map[string]interface{}{"domain": "docs.example", "url": "https://docs.example/" + path, "content_hash": hash, "content_length": 100, "agent_id": "reader"}
		if err := g.HandleEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	report("llms.txt", "first")
	if !cp.hasAlertType("web_content_new_domain") {
		t.Fatal("first domain should establish a baseline")
	}
	before := cp.count()
	report("llms.txt", "first")
	if cp.count() != before {
		t.Fatal("unchanged content should not produce a new finding")
	}
	report("other.md", "second")
	if !cp.hasAlertType("web_content_changed") {
		t.Fatal("a different URL shares the same domain baseline")
	}
	report("llms.txt", "third")
	report("llms.txt", "fourth")
	report("llms.txt", "fifth")
	if !cp.hasAlertType("web_content_rapid_changes") {
		t.Fatal("four reported hash changes should produce a rapid-change finding")
	}
}

func TestWebContentTracker_WindowResetAndDomainIsolation(t *testing.T) {
	wt := NewWebContentIntegrityTracker()
	wt.RecordContent("docs.example", "/a", "a", 100)
	if result := wt.RecordContent("other.example", "/a", "b", 200); !result.NewDomain || result.ContentChanged {
		t.Fatal("different domains must not share a baseline")
	}
	for _, hash := range []string{"b", "c", "d", "e"} {
		wt.RecordContent("docs.example", "/a", hash, 100)
	}
	wt.mu.Lock()
	wt.domains["docs.example"].ChangeWindow = time.Now().Add(-2 * time.Hour)
	wt.mu.Unlock()
	result := wt.RecordContent("docs.example", "/a", "e", 100)
	if result.RapidChanges || result.ChangeCount != 0 || result.ContentChanged {
		t.Fatalf("window reset should preserve the hash and reset change count: %+v", result)
	}
}
