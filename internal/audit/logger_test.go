package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func TestTerminalCheckpointDetectsTailTruncation(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewFileLogger(logFile)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := logger.LogEvent(Event{TraceID: fmt.Sprintf("trace-%d", i), Route: "/v1/chat", Action: ActionAllowed, ThreatCategory: ThreatCategoryNone, Severity: SeverityLow}); err != nil {
			t.Fatalf("failed to write event: %v", err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("failed to close audit logger: %v", err)
	}

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	res, err := VerifyLatestCheckpoint(bytes.NewReader(content))
	if err != nil || !res.Valid || res.TotalRecords != 2 {
		t.Fatalf("expected valid terminal checkpoint, got result=%+v err=%v", res, err)
	}

	// Cutting both the final event and its checkpoint used to look like a
	// valid shorter chain. Strict verification now rejects the missing trailer.
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	truncated := strings.Join(lines[:1], "\n")
	res, err = VerifyLatestCheckpoint(strings.NewReader(truncated))
	if err != nil {
		t.Fatalf("truncation verification returned error: %v", err)
	}
	if res.Valid || res.Reason != "missing terminal audit checkpoint" {
		t.Fatalf("expected tail truncation to be rejected, got %+v", res)
	}
}

func TestLegacyAuditLogRemainsVerifiable(t *testing.T) {
	event := Event{Timestamp: time.Now().UTC(), TraceID: "legacy", Route: "/v1/chat", Action: ActionAllowed, ThreatCategory: ThreatCategoryNone, Severity: SeverityLow, PrevRecordHash: GenesisHash}
	event.RecordHash = CalculateRecordHash(event)
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal legacy event: %v", err)
	}
	res, err := VerifyLatestCheckpoint(bytes.NewReader(data))
	if err != nil || !res.Valid {
		t.Fatalf("legacy audit log must remain verifiable, got result=%+v err=%v", res, err)
	}
}
