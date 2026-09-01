package waf

import (
	"encoding/base64"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf16"
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
)

// normalizeInput unescapes URL/HTML encoding to a fixed point and strips
// inline comment syntax, so signature matching sees the payload the way the
// downstream interpreter will — not the way the attacker typed it.
func normalizeInput(raw string) string {
	decoded := decodeSurface(raw)
	// Unwrap MySQL versioned comments to their live content first, then
	// collapse ordinary inline comments to a single space — so comments
	// used as whitespace substitutes (UNION/**/SELECT) still separate into
	// matchable keywords instead of hiding the payload.
	if strings.Contains(decoded, "/*") {
		decoded = sqlVersionedComment.ReplaceAllString(decoded, " $1 ")
		decoded = sqlInlineComment.ReplaceAllString(decoded, " ")
	}
	decoded = stripC0Controls(decoded)
	return decoded
}

func decodeSurface(raw string) string {
	// Decode UTF-7 before query unescaping. In a raw query, '+' is normally
	// converted to a space by QueryUnescape, which would destroy UTF-7 shift
	// sequences such as +ADw- (<) before we can inspect their meaning.
	decoded := raw
	if strings.Contains(raw, "+") && strings.Contains(raw, "-") {
		decoded = decodeUTF7(raw)
	}
	// Percent-decode to a fixed point (bounded) instead of a hardcoded 2-pass,
	// so N-times-encoded payloads (%2525.. etc.) still resolve.
	if strings.ContainsAny(decoded, "%+") {
		for i := 0; i < 5; i++ {
			next, err := url.QueryUnescape(decoded)
			if err != nil || next == decoded {
				break
			}
			decoded = next
		}
	}
	decoded = decodeOverlongASCII(decoded)
	// Decode HTML entities (&#x3a; / &colon; / etc.) to a bounded fixed point.
	if strings.Contains(decoded, "&") {
		for i := 0; i < 3; i++ {
			next := html.UnescapeString(decoded)
			if next == decoded {
				break
			}
			decoded = next
		}
	}
	return decoded
}

// normalizeSQLCompactInput is the second SQL lexer view. Some permissive SQL
// parsers accept comments inserted inside keywords (UNI/**/ON); the ordinary
// view must replace comments with whitespace for UNION/**/SELECT. Scanning
// both spaced and compact views prevents either parser interpretation from
// becoming a bypass.
func normalizeSQLCompactInput(raw string) string {
	decoded := decodeSurface(raw)
	if strings.Contains(decoded, "/*") {
		decoded = sqlVersionedComment.ReplaceAllString(decoded, "$1")
		decoded = sqlInlineComment.ReplaceAllString(decoded, "")
	}
	decoded = stripC0Controls(decoded)
	return collapseEmbeddedWhitespace(decoded)
}

func stripC0Controls(input string) string {
	first := -1
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c <= 0x08 || c == 0x0b || c == 0x0c || c >= 0x0e && c <= 0x1f || c == 0x7f {
			first = i
			break
		}
	}
	if first < 0 {
		return input
	}
	out := make([]byte, 0, len(input)-1)
	out = append(out, input[:first]...)
	for i := first; i < len(input); i++ {
		c := input[i]
		if c <= 0x08 || c == 0x0b || c == 0x0c || c >= 0x0e && c <= 0x1f || c == 0x7f {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// decodeUTF7 decodes bounded UTF-7 shift sequences. UTF-7 is obsolete, but
// legacy decoders and charset-confused upstreams still turn +ADw-script+AD4-
// into <script>. Invalid/non-UTF-7 '+' text is preserved verbatim.
func decodeUTF7(input string) string {
	if !strings.Contains(input, "+") {
		return input
	}
	var out strings.Builder
	for i := 0; i < len(input); {
		if input[i] != '+' {
			out.WriteByte(input[i])
			i++
			continue
		}
		end := strings.IndexByte(input[i+1:], '-')
		if end < 0 || end == 0 || end > 256 {
			out.WriteByte(input[i])
			i++
			continue
		}
		end += i + 1
		encoded := strings.ReplaceAll(input[i+1:end], ",", "/")
		raw, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil || len(raw) == 0 || len(raw)%2 != 0 {
			out.WriteByte(input[i])
			i++
			continue
		}
		units := make([]uint16, len(raw)/2)
		asciiOnly := true
		for j := range units {
			units[j] = uint16(raw[2*j])<<8 | uint16(raw[2*j+1])
			if units[j] < 0x20 || units[j] > 0x7e {
				asciiOnly = false
			}
		}
		// The WAF only needs the legacy ASCII-confusion form. Requiring
		// printable ASCII prevents ordinary form-urlencoded '+' separators
		// followed later by '-' (for example a SQL '--' comment) from being
		// misclassified as one giant UTF-7 shift sequence.
		if !asciiOnly {
			out.WriteByte(input[i])
			i++
			continue
		}
		out.WriteString(string(utf16.Decode(units)))
		i = end + 1
	}
	return out.String()
}

// decodeOverlongASCII canonicalizes legacy overlong UTF-8 encodings of ASCII
// punctuation. Go correctly rejects these as UTF-8, but a more permissive
// upstream may decode C0 AF as '/', creating a parser differential.
func decodeOverlongASCII(input string) string {
	if !strings.ContainsAny(input, "\xc0\xc1\xe0\xf0") {
		return input
	}
	b := []byte(input)
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if i+1 < len(b) && (b[i] == 0xc0 || b[i] == 0xc1) {
			if b[i+1]&0xc0 == 0x80 {
				v := (b[i]&0x1f)<<6 | (b[i+1] & 0x3f)
				if v <= 0x7f {
					out = append(out, v)
					i += 2
					continue
				}
			}
			// Some permissive decoders discard a stray C0/C1 lead byte and
			// retain the following ASCII separator (e.g. C0 5C -> '\\').
			if b[i+1] == '.' || b[i+1] == '/' || b[i+1] == '\\' {
				out = append(out, b[i+1])
				i += 2
				continue
			}
		}
		out = append(out, b[i])
		i++
	}
	return string(out)
}

func collapseEmbeddedWhitespace(input string) string {
	if !strings.ContainsAny(input, "\t\r\n") {
		return input
	}
	b := []byte(input)
	out := make([]byte, 0, len(b))
	for i, c := range b {
		if c != '\t' && c != '\r' && c != '\n' {
			out = append(out, c)
			continue
		}
		prevWord := i > 0 && isASCIIWordByte(b[i-1])
		nextWord := i+1 < len(b) && isASCIIWordByte(b[i+1])
		if prevWord && nextWord {
			continue
		}
		out = append(out, ' ')
	}
	return string(out)
}

func isASCIIWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func containsASCIIFold(input, needle string) bool {
	if len(needle) == 0 || len(needle) > len(input) {
		return false
	}
	for i := 0; i+len(needle) <= len(input); i++ {
		if strings.EqualFold(input[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func containsASCIIWordFold(input, word string) bool {
	for start := 0; start+len(word) <= len(input); start++ {
		if !strings.EqualFold(input[start:start+len(word)], word) {
			continue
		}
		leftOK := start == 0 || !isASCIIWordByte(input[start-1])
		right := start + len(word)
		rightOK := right == len(input) || !isASCIIWordByte(input[right])
		if leftOK && rightOK {
			return true
		}
	}
	return false
}

// queryValueViews exposes decoded parameter values individually and in the
// order a backend may concatenate them. This closes HPP parser differentials
// where UN&x=ION SE&y=LECT becomes UNION SELECT after framework binding.
func queryValueViews(rawQuery string) []string {
	if !strings.Contains(rawQuery, "&") || !hppCandidate(rawQuery) {
		return nil
	}
	parts := strings.Split(rawQuery, "&")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		_, value, found := strings.Cut(part, "=")
		if !found {
			value = part
		}
		value = normalizeInput(value)
		if value != "" {
			values = append(values, value)
		}
	}
	if len(values) < 2 {
		return values
	}
	return append(values, strings.Join(values, ""))
}

func hppCandidate(rawQuery string) bool {
	if strings.ContainsAny(rawQuery, "'\";<>`|$\\") ||
		strings.Contains(rawQuery, "--") || strings.Contains(rawQuery, "/*") ||
		strings.Contains(rawQuery, "..") {
		return true
	}
	if !strings.Contains(rawQuery, "%") {
		return false
	}
	return containsASCIIFold(rawQuery, "%27") || containsASCIIFold(rawQuery, "%22") ||
		containsASCIIFold(rawQuery, "%3c") || containsASCIIFold(rawQuery, "%3e") ||
		containsASCIIFold(rawQuery, "%2e")
}

// Inspect scans request parameters, path, headers, and body for malicious payloads.
func (e *Engine) Inspect(method, path, query string, headers http.Header, body []byte) *WAFResult {
	// Normalize target surfaces
	normPath := normalizeInput(path)
	normQuery := normalizeInput(query)
	bodyText := string(body)
	normBody := normalizeInput(bodyText)
	queryViews := queryValueViews(query)
	var headerStorage [16]string
	headerViews := headerStorage[:0]
	for hKey, values := range headers {
		if !isScannedHeader(hKey) {
			continue
		}
		for _, value := range values {
			headerViews = append(headerViews, normalizeInput(value))
		}
	}
	compactSQLPath := normPath
	compactSQLQuery := normQuery
	compactSQLBody := normBody
	if needsCompactView(path) {
		compactSQLPath = normalizeSQLCompactInput(path)
	}
	if needsCompactView(query) {
		compactSQLQuery = normalizeSQLCompactInput(query)
	}
	if needsCompactView(bodyText) {
		compactSQLBody = normalizeSQLCompactInput(bodyText)
	}

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
		if res := scanViews(queryViews, checkPathTraversal); res != nil {
			return res
		}
		if res := checkPathTraversal(normBody); res != nil {
			return res
		}
		if res := scanViews(headerViews, checkPathTraversal); res != nil {
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
		if res := scanViews(queryViews, checkCommandInjectionStrict); res != nil {
			return res
		}
		if res := scanViews(headerViews, checkCommandInjectionStrict); res != nil {
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
		if compactSQLPath != normPath {
			if res := checkSQLiCompact(compactSQLPath); res != nil {
				return res
			}
		}
		if res := checkSQLi(normQuery); res != nil {
			return res
		}
		if compactSQLQuery != normQuery {
			if res := checkSQLiCompact(compactSQLQuery); res != nil {
				return res
			}
		}
		if res := scanViews(queryViews, checkSQLi); res != nil {
			return res
		}
		if res := checkSQLi(normBody); res != nil {
			return res
		}
		if compactSQLBody != normBody {
			if res := checkSQLiCompact(compactSQLBody); res != nil {
				return res
			}
		}
		if res := scanViews(headerViews, checkSQLi); res != nil {
			return res
		}
		if res := scanHeadersCompactSQL(headers); res != nil {
			return res
		}
	}

	// 4. XSS Inspection — path, query, body, and headers. Path segments are
	// reflected into error pages and breadcrumbs as often as query values.
	if e.config.EnableXSS {
		if res := checkXSS(normPath); res != nil {
			return res
		}
		if strings.ContainsAny(normPath, "\t\r\n") {
			if res := checkXSS(collapseEmbeddedWhitespace(normPath)); res != nil {
				return res
			}
		}
		if res := checkXSS(normQuery); res != nil {
			return res
		}
		if strings.ContainsAny(normQuery, "\t\r\n") {
			if res := checkXSS(collapseEmbeddedWhitespace(normQuery)); res != nil {
				return res
			}
		}
		if res := scanViews(queryViews, checkXSS); res != nil {
			return res
		}
		if res := checkXSS(normBody); res != nil {
			return res
		}
		if strings.ContainsAny(normBody, "\t\r\n") {
			if res := checkXSS(collapseEmbeddedWhitespace(normBody)); res != nil {
				return res
			}
		}
		if res := scanViews(headerViews, checkXSS); res != nil {
			return res
		}
		if res := scanViews(headerViews, func(value string) *WAFResult {
			if !strings.ContainsAny(value, "\t\r\n") {
				return nil
			}
			return checkXSS(collapseEmbeddedWhitespace(value))
		}); res != nil {
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

// The selected headers are attacker-controlled, commonly reflected, logged,
// or used as lookup keys, and never expected to carry injection syntax.
//
// Cookie and Authorization matter most and were the longest-missing: both
// are fully attacker-controlled and both are routinely fed straight into a
// session or token lookup query, which is exactly the sink SQLi needs.
// Restricting the scan to Referer/User-Agent/X-Forwarded-For left the
// highest-value header sinks unscanned.
func isScannedHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Referer", "User-Agent", "X-Forwarded-For", "Cookie", "Authorization",
		"X-Forwarded-Host", "X-Real-Ip", "Origin", "X-Api-Key":
		return true
	default:
		return false
	}
}

func scanViews(views []string, checkFn func(string) *WAFResult) *WAFResult {
	for _, view := range views {
		if res := checkFn(view); res != nil {
			return res
		}
	}
	return nil
}

func scanHeadersCompactSQL(headers http.Header) *WAFResult {
	for hKey, values := range headers {
		if !isScannedHeader(hKey) {
			continue
		}
		for _, value := range values {
			if !needsCompactView(value) {
				continue
			}
			if res := checkSQLiCompact(normalizeSQLCompactInput(value)); res != nil {
				return res
			}
		}
	}
	return nil
}

func needsCompactView(input string) bool {
	return strings.Contains(input, "/*") || strings.ContainsAny(input, "\x00\t\r\n")
}

func truncateSample(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
