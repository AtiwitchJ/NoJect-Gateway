package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTamperEvidentAuditLogger(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileLogger(logFile)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer logger.Close()

	// 1. Log multiple events
	events := []Event{
		{
			TraceID:        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			ClientID:       "client-123",
			ClientIP:       "192.168.1.50",
			Route:          "/v1/chat/completions",
			Action:         ActionAllowed,
			ThreatCategory: ThreatCategoryNone,
			Severity:       SeverityLow,
			Confidence:     0.0,
			Timestamp:      time.Now().UTC(),
		},
		{
			TraceID:        "00-6a92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b8-01",
			ClientID:       "attacker-999",
			ClientIP:       "10.0.0.1",
			Route:          "/api/users",
			Action:         ActionBlocked,
			ThreatCategory: ThreatCategorySQLi,
			Severity:       SeverityCritical,
			Confidence:     1.0,
			Reason:         "SQL Injection detected: UNION SELECT construct",
			Timestamp:      time.Now().UTC(),
		},
		{
			TraceID:        "00-8b92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b9-01",
			ClientID:       "user-777",
			ClientIP:       "172.16.0.2",
			Route:          "/v1/chat/completions",
			Action:         ActionMasked,
			ThreatCategory: ThreatCategoryPII,
			Severity:       SeverityMedium,
			Confidence:     0.95,
			Reason:         "Masked Thai National ID and Phone number",
			Timestamp:      time.Now().UTC(),
		},
	}

	for _, ev := range events {
		if err := logger.LogEvent(ev); err != nil {
			t.Fatalf("failed to log event: %v", err)
		}
	}

	// 2. Verify legitimate log integrity
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	res, err := VerifyChain(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected audit chain to be valid, got invalid at index %d", res.BrokenAtIndex)
	}
	if res.TotalRecords != 3 {
		t.Errorf("expected 3 records, got %d", res.TotalRecords)
	}

	// 3. Test Tampering: Modify a record in the middle
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// Attacker tries to change ActionBlocked to ActionAllowed
	tamperedLine := strings.Replace(lines[1], `"action":"BLOCKED"`, `"action":"ALLOWED"`, 1)
	tamperedContent := strings.Join([]string{lines[0], tamperedLine, lines[2]}, "\n")

	tamperRes, err := VerifyChain(strings.NewReader(tamperedContent))
	if err != nil {
		t.Fatalf("tamper verification returned error: %v", err)
	}
	if tamperRes.Valid {
		t.Fatal("expected tamper detection to FAIL, but it reported valid!")
	}
	if tamperRes.BrokenAtIndex != 1 {
		t.Errorf("expected tampering detected at index 1, got %d", tamperRes.BrokenAtIndex)
	}

	// 4. Test Deletion Tampering: Remove the 2nd record entirely
	deletedContent := strings.Join([]string{lines[0], lines[2]}, "\n")
	delRes, err := VerifyChain(strings.NewReader(deletedContent))
	if err != nil {
		t.Fatalf("deletion verification returned error: %v", err)
	}
	if delRes.Valid {
		t.Fatal("expected deletion detection to FAIL, but it reported valid!")
	}
	if delRes.BrokenAtIndex != 1 {
		t.Errorf("expected broken chain at index 1 after deletion, got %d", delRes.BrokenAtIndex)
	}
}
