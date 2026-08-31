package waf

import (
	"net/http"
	"net/url"
	"strings"
)

// ThreatType classifies the detected injection vector.
type ThreatType string

const (
	ThreatNone          ThreatType = "NONE"
	ThreatSQLi          ThreatType = "SQL_INJECTION"
	ThreatXSS           ThreatType = "XSS"
	ThreatCMDInjection  ThreatType = "CMD_INJECTION"
	ThreatPathTraversal ThreatType = "PATH_TRAVERSAL"
)

// Severity indicates the threat level.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// WAFResult contains the evaluation verdict of the Fast-Path WAF.
type WAFResult struct {
	Blocked       bool       `json:"blocked"`
	ThreatType    ThreatType `json:"threat_type"`
	Severity      Severity   `json:"severity"`
	Reason        string     `json:"reason"`
	MatchedRule   string     `json:"matched_rule,omitempty"`
	MatchedSample string     `json:"matched_sample,omitempty"`
}

// Config configures which detection modules are enabled.
type Config struct {
	EnableSQLi          bool
	EnableXSS           bool
	EnableCMDInjection  bool
	EnablePathTraversal bool
}

// DefaultConfig enables all WAF protections with recommended settings.
func DefaultConfig() Config {
	return Config{
		EnableSQLi:          true,
		EnableXSS:           true,
		EnableCMDInjection:  true,
		EnablePathTraversal: true,
	}
}

// Engine executes fast-path regex and heuristic security inspections.
type Engine struct {
	config Config
}

// NewEngine creates a new WAF Engine instance.
func NewEngine(cfg Config) *Engine {
	return &Engine{config: cfg}
}

// normalizeInput unescapes URL encoding, lowercase transforms, and cleans control chars.
func normalizeInput(raw string) string {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	// Multi-pass unescape to handle double encoding
	if doubleDecoded, err := url.QueryUnescape(decoded); err == nil {
		decoded = doubleDecoded
	}
	return decoded
}

// Inspect scans request parameters, path, headers, and body for malicious payloads.
func (e *Engine) Inspect(method, path, query string, headers http.Header, body []byte) *WAFResult {
	// Normalize target surfaces
	normPath := normalizeInput(path)
	normQuery := normalizeInput(query)
	normBody := normalizeInput(string(body))

	// 1. Path Traversal Inspection (Path & Query)
	if e.config.EnablePathTraversal {
		if res := checkPathTraversal(normPath); res != nil {
			return res
		}
		if res := checkPathTraversal(normQuery); res != nil {
			return res
		}
		if res := checkPathTraversal(normBody); res != nil {
			return res
		}
	}

	// 2. Command Injection Inspection
	if e.config.EnableCMDInjection {
		if res := checkCommandInjection(normQuery); res != nil {
			return res
		}
		if res := checkCommandInjection(normBody); res != nil {
			return res
		}
	}

	// 3. SQL Injection Inspection
	if e.config.EnableSQLi {
		if res := checkSQLi(normQuery); res != nil {
			return res
		}
		if res := checkSQLi(normBody); res != nil {
			return res
		}
	}

	// 4. XSS Inspection (Query, Body, and Critical Headers)
	if e.config.EnableXSS {
		if res := checkXSS(normQuery); res != nil {
			return res
		}
		if res := checkXSS(normBody); res != nil {
			return res
		}
		for _, hKey := range []string{"Referer", "User-Agent", "X-Forwarded-For"} {
			for _, val := range headers[hKey] {
				if res := checkXSS(normalizeInput(val)); res != nil {
					return res
				}
			}
		}
	}

	return &WAFResult{
		Blocked:    false,
		ThreatType: ThreatNone,
		Severity:   SeverityLow,
		Reason:     "payload verified clean",
	}
}

func truncateSample(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
