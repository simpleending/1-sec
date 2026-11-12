package datapoisoning

import (
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func TestInferenceEventAliases(t *testing.T) {
	for _, eventType := range []string{"inference_result", "model_inference", "prediction"} {
		for _, confidence := range []float64{0.05, 0.9} {
			t.Run(eventType+"/"+fmtConfidence(confidence), func(t *testing.T) {
				cp := makeCapturingPipeline()
				module := startedModuleWithPipeline(t, cp)
				t.Cleanup(func() { _ = module.Stop() })
				event := core.NewSecurityEvent("sensor", eventType, core.SeverityInfo, "prediction observed")
				event.Details["model_id"] = "test-model"
				event.Details["confidence"] = confidence
				if err := module.HandleEvent(event); err != nil {
					t.Fatal(err)
				}
				if got := cp.hasAlertType("adversarial_input"); got != (confidence < 0.1) {
					t.Fatalf("low-confidence alert = %v for confidence %v", got, confidence)
				}
				// A benign prediction must also reach the baseline, not only the alert branch.
				module.driftMonitor.mu.RLock()
				defer module.driftMonitor.mu.RUnlock()
				if module.driftMonitor.models["test-model"] == nil {
					t.Fatal("prediction never reached the drift baseline")
				}
			})
		}
	}
}

func fmtConfidence(confidence float64) string {
	if confidence < 0.1 {
		return "low-confidence"
	}
	return "normal-confidence"
}
