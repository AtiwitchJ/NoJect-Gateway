package waf

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
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

var (
	// MySQL versioned comments (/*!50000 SELECT ... */) are NOT no-ops —
	// the server executes the content when its version matches. Unwrap to
	// the inner content (not strip to nothing), or the real payload
	// underneath goes invisible to every downstream signature check.
	sqlVersionedComment = regexp.MustCompile(`/\*!\d*(.*?)\*/`)
	sqlInlineComment    = regexp.MustCompile(`/\*.*?\*/`)
	// NUL and other C0 control characters (except \t \n \r) are stripped:
	// several downstream parsers drop them silently, so "<scr\x00ipt>"
	// reaches the browser as "<script>" while defeating naive matching here.
	controlChars = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

// normalizeInput unescapes URL/HTML encoding to a fixed point and strips
// inline comment syntax, so signature matching sees the payload the way the
// downstream interpreter will — not the way the attacker typed it.
func normalizeInput(raw string) string {
	decoded := raw
	// Percent-decode to a fixed point (bounded) instead of a hardcoded 2-pass,
	// so N-times-encoded payloads (%2525.. etc.) still resolve.
	for i := 0; i < 5; i++ {
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	// Decode HTML entities (&#x3a; / &colon; / etc.) — attackers use these to
	// hide literal tokens like "javascript:" from substring matching.
	decoded = html.UnescapeString(decoded)
	// Unwrap MySQL versioned comments to their live content first, then
	// collapse ordinary inline comments to a single space — so comments
	// used as whitespace substitutes (UNION/**/SELECT) still separate into
	// matchable keywords instead of hiding the payload.
	decoded = sqlVersionedComment.ReplaceAllString(decoded, " $1 ")
	decoded = sqlInlineComment.ReplaceAllString(decoded, " ")
	// Drop embedded control characters last, so a NUL planted mid-keyword
	// cannot split a token that the downstream parser will see intact.
	decoded = controlChars.ReplaceAllString(decoded, "")
	return decoded
}

// Inspect scans request parameters, path, headers, and body for malicious payloads.
func (e *Engine) Inspect(method, path, query string, headers http.Header, body []byte) *WAFResult {
	// Normalize target surfaces
	normPath := normalizeInput(path)
	normQuery := normalizeInput(query)
	normBody := normalizeInput(string(body))

	// 1. Path Traversal Inspection — path, query, body, and headers. Body
	// is in scope: LFI-style attacks pass "../" through a JSON field
	// naming a file (e.g. {"file":"../../etc/passwd"}), which this gateway
	// fronts for tool-calling/agentic routes.
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
		if res := scanHeaders(headers, checkPathTraversal); res != nil {
			return res
		}
	}

	// 2. Command Injection Inspection — path, query, body, and headers.
	// Body is in scope deliberately: this gateway fronts LLM/agentic
	// tool-calling routes where the request body IS the content a
	// downstream tool may execute, so a subshell/pipe-to-shell attempt
	// embedded in a chat prompt or tool-call payload is a real attack
	// surface, not noise. The broad command allowlist in cmdPipeOrChain
	// does carry real false-positive risk against ordinary prose containing
	// ";"/"|"/"&&" — track this with the false-positive corpus test (see
	// design spec §8) rather than by blinding the check to the body.
	if e.config.EnableCMDInjection {
		// Path, query and headers get the strict syntax-level rules: shell
		// metacharacters have no legitimate use there, so a separator
		// followed by a command token is an attack regardless of which
		// binary is named.
		if res := checkCommandInjectionStrict(normPath); res != nil {
			return res
		}
		if res := checkCommandInjectionStrict(normQuery); res != nil {
			return res
		}
		if res := scanHeaders(headers, checkCommandInjectionStrict); res != nil {
			return res
		}
		// Bodies keep the narrower named-binary rules — prose and code
		// legitimately contain ";" and "|", so the strict rule would
		// misfire on ordinary content.
		if res := checkCommandInjection(normBody); res != nil {
			return res
		}
	}

	// 3. SQL Injection Inspection — path, query, body, and headers.
	// Path is in scope because REST-style routes put user input directly in
	// path segments (/api/users/{id}), which reaches the same query builder
	// as a query parameter. Headers are in scope because values like
	// Cookie and Authorization are routinely used as lookup keys.
	if e.config.EnableSQLi {
		if res := checkSQLi(normPath); res != nil {
			return res
		}
		if res := checkSQLi(normQuery); res != nil {
			return res
		}
		if res := checkSQLi(normBody); res != nil {
			return res
		}
		if res := scanHeaders(headers, checkSQLi); res != nil {
			return res
		}
	}

	// 4. XSS Inspection — path, query, body, and headers. Path segments are
	// reflected into error pages and breadcrumbs as often as query values.
	if e.config.EnableXSS {
		if res := checkXSS(normPath); res != nil {
			return res
		}
		if res := checkXSS(normQuery); res != nil {
			return res
		}
		if res := checkXSS(normBody); res != nil {
			return res
		}
		if res := scanHeaders(headers, checkXSS); res != nil {
			return res
		}
	}

	return &WAFResult{
		Blocked:    false,
		ThreatType: ThreatNone,
		Severity:   SeverityLow,
		Reason:     "payload verified clean",
	}
}

// scannedHeaders are the headers inspected for injection payloads —
// attacker-controlled, commonly reflected, logged, or used as lookup keys,
// and never expected to carry SQL/shell/traversal syntax.
//
// Cookie and Authorization matter most and were the longest-missing: both
// are fully attacker-controlled and both are routinely fed straight into a
// session or token lookup query, which is exactly the sink SQLi needs.
// Restricting the scan to Referer/User-Agent/X-Forwarded-For left the
// highest-value header sinks unscanned.
var scannedHeaders = []string{
	"Referer",
	"User-Agent",
	"X-Forwarded-For",
	"Cookie",
	"Authorization",
	"X-Forwarded-Host",
	"X-Real-IP",
	"Origin",
	"X-Api-Key",
}

// scanHeaders runs checkFn against each scanned header value, normalized.
func scanHeaders(headers http.Header, checkFn func(string) *WAFResult) *WAFResult {
	for _, hKey := range scannedHeaders {
		for _, val := range headers[hKey] {
			if res := checkFn(normalizeInput(val)); res != nil {
				return res
			}
		}
	}
	return nil
}

func truncateSample(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
