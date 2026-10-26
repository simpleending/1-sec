package tokenvault

import (
	"context"
	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
	"testing"
)

func TestTokenExchangeEventsPopulateAbuseCounter(t *testing.T) {
	p := core.NewAlertPipeline(zerolog.Nop(), 100)
	tv := NewTokenVault(context.Background(), p, core.DefaultConfig(), zerolog.Nop())
	for i := 0; i < 21; i++ {
		e := core.NewSecurityEvent("test", "token_exchange", core.SeverityInfo, "")
		e.Details["agent_id"] = "agent"
		e.Details["connection"] = "github"
		tv.handleTokenExchange(e)
	}
	if len(p.GetAlerts(core.SeverityHigh, 100)) == 0 {
		t.Fatal("token abuse silently missed")
	}
}
