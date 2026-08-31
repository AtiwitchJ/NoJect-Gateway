package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Action represents the outcome of the security inspection.
type Action string

const (
	ActionAllowed Action = "ALLOWED"
	ActionBlocked Action = "BLOCKED"
	ActionMasked  Action = "MASKED"
)

// ThreatCategory defines the category for audit categorization.
type ThreatCategory string

const (
	ThreatCategoryNone            ThreatCategory = "NONE"
	ThreatCategorySQLi            ThreatCategory = "SQL_INJECTION (CWE-89)"
	ThreatCategoryXSS             ThreatCategory = "XSS (CWE-79)"
	ThreatCategoryCommandInjection ThreatCategory = "COMMAND_INJECTION (CWE-78)"
	ThreatCategoryPathTraversal   ThreatCategory = "PATH_TRAVERSAL (CWE-22)"
	ThreatCategoryPromptInjection ThreatCategory = "PROMPT_INJECTION (MITRE AML.T0054 / OWASP LLM01)"
	ThreatCategoryJailbreak       ThreatCategory = "JAILBREAK (MITRE AML.T0051 / OWASP LLM01)"
	ThreatCategoryPIILeak         ThreatCategory = "PII_LEAK (OWASP LLM02 / ISO 42001 B.7.2)"
	ThreatCategoryPII             ThreatCategory = "PII_LEAK (OWASP LLM02 / ISO 42001 B.7.2)"
	ThreatCategoryCMDInjection    ThreatCategory = "COMMAND_INJECTION (CWE-78)"
	ThreatCategoryCanaryLeak      ThreatCategory = "CANARY_LEAK (OWASP LLM07 / MITRE AML.T0043)"
	ThreatCategoryAuthFailure     ThreatCategory = "AUTH_FAILURE (ISO 27001 A.5.15)"
)

// Severity indicates the threat level for ISO 27001 event classification.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Event is an ISO 27001 / ISO 42001 compliant audit log entry.
type Event struct {
	Timestamp      time.Time      `json:"timestamp"`
	TraceID        string         `json:"trace_id"`
	ClientID       string         `json:"client_id,omitempty"`
	ClientIP       string         `json:"client_ip"`
	Route          string         `json:"route"`
	Action         Action         `json:"action"`
	ThreatCategory ThreatCategory `json:"threat_category"`
	Severity       Severity       `json:"severity"`
	Confidence     float64        `json:"confidence"`
	Reason         string         `json:"reason,omitempty"`
	MatchedRule    string         `json:"matched_rule,omitempty"`

	// Cryptographic Hash Chaining fields
	PrevRecordHash string `json:"prev_record_hash"`
	RecordHash     string `json:"record_hash"`
}

// Logger defines the interface for emitting audit events.
type Logger interface {
	LogEvent(event Event) error
	Close() error
}

// FileLogger appends tamper-evident audit records to a JSON Lines file.
type FileLogger struct {
	mu           sync.Mutex
	file         *os.File
	lastHash     string
	genesisBlock string
}

// GenesisHash is the seed hash for the cryptographic chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// NewFileLogger initializes or opens an audit log file and recovers the last hash.
func NewFileLogger(filePath string) (*FileLogger, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), 0750); err != nil {
		return nil, fmt.Errorf("failed to create log dir: %w", err)
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file: %w", err)
	}

	lastHash := GenesisHash

	// Read existing records to find the latest valid hash if file is not empty
	stat, err := file.Stat()
	if err == nil && stat.Size() > 0 {
		recoveredHash, err := RecoverLastHash(file)
		if err == nil && recoveredHash != "" {
			lastHash = recoveredHash
		}
	}

	return &FileLogger{
		file:         file,
		lastHash:     lastHash,
		genesisBlock: GenesisHash,
	}, nil
}

// LogEvent writes a single hashed audit record to the log.
func (l *FileLogger) LogEvent(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	event.PrevRecordHash = l.lastHash
	event.RecordHash = CalculateRecordHash(event)

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write audit record: %w", err)
	}

	l.lastHash = event.RecordHash
	return nil
}

// Close flushes and closes the audit log file.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
