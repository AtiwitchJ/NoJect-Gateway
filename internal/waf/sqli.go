package waf

import (
	"regexp"
)

var (
	// SQLi Rules compiled once
	sqliUnionSelect = regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b`)
	sqliBooleanTrue = regexp.MustCompile(`(?i)(['"]\s*OR\s+['"]?1['"]?\s*=\s*['"]?1|['"]\s*OR\s+['"][a-zA-Z0-9]+['"]\s*=\s*['"][a-zA-Z0-9]+|OR\s+1\s*=\s*1\s*(--|#|/\*))`)
	sqliStacked     = regexp.MustCompile(`(?i);\s*(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|EXEC\s*\()\b`)
	sqliTimeDelay   = regexp.MustCompile(`(?i)\b(SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(\s*\d+|WAITFOR\s+DELAY\s+['"]\d+)`)
	sqliCommentHack = regexp.MustCompile(`(?i)['"]\s*(--|#|/\*).*?\b(SELECT|WHERE|AND|OR)\b`)
)

func checkSQLi(input string) *WAFResult {
	if len(input) == 0 {
		return nil
	}

	if match := sqliUnionSelect.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatSQLi,
			Severity:      SeverityCritical,
			Reason:        "SQL Injection detected: UNION SELECT construct",
			MatchedRule:   "sqli_union_select",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := sqliBooleanTrue.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatSQLi,
			Severity:      SeverityHigh,
			Reason:        "SQL Injection detected: Boolean tautology (OR 1=1 / boolean bypass)",
			MatchedRule:   "sqli_boolean_tautology",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := sqliStacked.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatSQLi,
			Severity:      SeverityCritical,
			Reason:        "SQL Injection detected: Stacked destructive query",
			MatchedRule:   "sqli_stacked_destructive",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := sqliTimeDelay.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatSQLi,
			Severity:      SeverityHigh,
			Reason:        "SQL Injection detected: Time-based blind exfiltration function",
			MatchedRule:   "sqli_time_delay",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := sqliCommentHack.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatSQLi,
			Severity:      SeverityMedium,
			Reason:        "SQL Injection detected: Comment-based syntax breaking",
			MatchedRule:   "sqli_comment_bypass",
			MatchedSample: truncateSample(match, 50),
		}
	}

	return nil
}
