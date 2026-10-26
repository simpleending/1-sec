package datapoisoning

import (
	"github.com/1sec-project/1sec/internal/core"
	"testing"
)

func TestLegacyPickleBuiltinReferencesAreDetected(t *testing.T) {
	for _, function := range []string{"eval", "exec", "system"} {
		e := core.NewSecurityEvent("test", "model_download", core.SeverityInfo, "")
		e.RawData = []byte("c__builtin__\n" + function + "\n")
		if detectSuspiciousModelPayload(e) == "" {
			t.Fatal(function)
		}
	}
	e := core.NewSecurityEvent("test", "model_download", core.SeverityInfo, "")
	e.RawData = []byte("ordinary model metadata")
	if detectSuspiciousModelPayload(e) != "" {
		t.Fatal("benign content flagged")
	}
}
