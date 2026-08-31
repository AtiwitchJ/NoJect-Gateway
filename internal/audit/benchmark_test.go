package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func Benchmark_AuditLogger_HashChaining(b *testing.B) {
	tmpDir := b.TempDir()
	logFile := filepath.Join(tmpDir, "bench_audit.log")
	logger, err := NewFileLogger(logFile)
	if err != nil {
		b.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	event := Event{
		TraceID:        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		ClientID:       "client-benchmark",
		ClientIP:       "192.168.1.1",
		Route:          "/v1/chat/completions",
		Action:         ActionBlocked,
		ThreatCategory: ThreatCategorySQLi,
		Severity:       SeverityCritical,
		Confidence:     1.0,
		Reason:         "SQL Injection detected",
		Timestamp:      time.Now().UTC(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.LogEvent(event)
	}
}
