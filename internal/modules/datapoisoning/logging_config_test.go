package datapoisoning

import (
	"github.com/1sec-project/1sec/internal/core"
	"testing"
)

func TestModelLoggingConfigExecutionIsObserved(t *testing.T) {
	for _, config := range []string{
		"[handler_console]\nclass=(__import__('os').system('example'), logging.StreamHandler)[1]\nargs=()",
		"[handler_console]\nclass=StreamHandler\nargs=(\n  __import__ ('subprocess').run(['example']),\n)",
	} {
		cp := makeCapturingPipeline()
		g := startedModuleWithPipeline(t, cp)
		defer g.Stop()
		e := core.NewSecurityEvent("model-gateway", "model_download", core.SeverityInfo, "bundle review")
		e.Details["model_name"] = "segmentation-model"
		e.Details["hash"] = "reviewed-weights-digest"
		e.Details["model_config"] = config
		if err := g.HandleEvent(e); err != nil {
			t.Fatal(err)
		}
		if !cp.hasAlertType("model_logging_config_execution") {
			t.Fatal("executable bundle configuration was missed")
		}
	}
}

func TestOrdinaryModelLoggingConfigurationRemainsQuiet(t *testing.T) {
	for _, config := range []string{
		"[handler_console]\nclass=StreamHandler\nargs=(sys.stdout,)\nformatter=default",
		"[model]\ndescription=Documentation discusses __import__('os') but is not a logging handler",
		"[handler_console]\nclass=StreamHandler\nargs=()\n[formatter_default]\nformat=literal __import__('os') text",
	} {
		cp := makeCapturingPipeline()
		g := startedModuleWithPipeline(t, cp)
		defer g.Stop()
		e := core.NewSecurityEvent("test", "model_download", core.SeverityInfo, "")
		e.Details["model_name"] = "ordinary-model"
		e.Details["model_config"] = config
		if err := g.HandleEvent(e); err != nil {
			t.Fatal(err)
		}
		if cp.hasAlertType("model_logging_config_execution") {
			t.Fatal("ordinary configuration treated as execution")
		}
	}
}
