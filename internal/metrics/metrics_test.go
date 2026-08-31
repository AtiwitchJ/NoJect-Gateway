package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestMetricsCollector(t *testing.T) {
	c := NewCollector(10)

	// Record 3 events
	c.RecordRequest(200, "ALLOWED", "NONE", 150*time.Microsecond, 20*time.Millisecond, 50*time.Millisecond, nil)
	c.RecordRequest(403, "BLOCKED", "PROMPT_INJECTION", 200*time.Microsecond, 25*time.Millisecond, 0, &SecurityEvent{
		TraceID:        "00-trace-1-01",
		ClientID:       "user-1",
		ClientIP:       "10.0.0.1",
		Route:          "/v1/chat/completions",
		Action:         "BLOCKED",
		ThreatCategory: "PROMPT_INJECTION",
		Severity:       "CRITICAL",
		Reason:         "Prompt Injection detected",
	})
	c.RecordRequest(200, "MASKED", "PII_DETECTED", 100*time.Microsecond, 15*time.Millisecond, 40*time.Millisecond, &SecurityEvent{
		TraceID:        "00-trace-2-01",
		ClientID:       "user-2",
		ClientIP:       "10.0.0.2",
		Route:          "/v1/chat/completions",
		Action:         "MASKED",
		ThreatCategory: "PII_DETECTED",
		Severity:       "MEDIUM",
		Reason:         "Masked Phone",
	})

	snap := c.Snapshot()
	if snap.TotalRequests != 3 {
		t.Errorf("expected 3 total requests, got %d", snap.TotalRequests)
	}
	if snap.AllowedRequests != 1 {
		t.Errorf("expected 1 allowed request, got %d", snap.AllowedRequests)
	}
	if snap.BlockedRequests != 1 {
		t.Errorf("expected 1 blocked request, got %d", snap.BlockedRequests)
	}
	if snap.MaskedRequests != 1 {
		t.Errorf("expected 1 masked request, got %d", snap.MaskedRequests)
	}
	if snap.ThreatBreakdown["PROMPT_INJECTION"] != 1 {
		t.Errorf("expected 1 PROMPT_INJECTION, got %d", snap.ThreatBreakdown["PROMPT_INJECTION"])
	}
	if len(snap.RecentEvents) != 2 {
		t.Errorf("expected 2 recent security events, got %d", len(snap.RecentEvents))
	}

	prom := c.PrometheusExport()
	if !strings.Contains(prom, "noject_requests_total 3") {
		t.Errorf("expected prom to contain 'noject_requests_total 3', got:\n%s", prom)
	}
	if !strings.Contains(prom, `noject_threats_detected_total{threat="PROMPT_INJECTION"} 1`) {
		t.Errorf("expected prom to contain threat metric, got:\n%s", prom)
	}
}
