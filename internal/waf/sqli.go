package waf

import (
	"regexp"
	"strings"
)

var (
	// SQLi Rules compiled once
	sqliUnionSelect        = regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b`)
	sqliUnionSelectCompact = regexp.MustCompile(`(?i)\bUNION(?:ALL)?SELECT`)
	// Widened from a hardcoded "1=1"/equality-only tautology to any
	// OR-conjunction against a quoted comparison, covering LIKE/IN/</>
	// tautologies (' OR 'x' LIKE 'x, ' OR 1<2, ' OR 'a' IN ('a')) as well
	// as the original 1=1 form.
	// Matches OR *and* AND conjunctions. Blind-SQLi enumeration is driven
	// almost entirely by AND (' AND '1'='1 vs ' AND '1'='2 to compare
	// responses), so anchoring on OR alone missed the most common
	// data-extraction technique outright.
	sqliBooleanTrue = regexp.MustCompile(`(?i)(['"]\s*(OR|AND)\s+['"]?1['"]?\s*=\s*['"]?1|['"]\s*(OR|AND)\s+['"]?[a-zA-Z0-9]+['"]?\s*(=|<>|!=|>|<|LIKE|IN)\s*['"(]?[a-zA-Z0-9]+|['"]?\s*(OR|AND)\s+\(\s*1\s*\)\s*=\s*\(\s*1\s*\)|\b(OR|AND)\s+1\s*=\s*1\b)`)
	sqliStacked     = regexp.MustCompile(`(?i);\s*(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|EXEC\s*\()\b`)
	// Time-based blind SQLi across engines, not just MySQL/MSSQL: PostgreSQL
	// uses pg_sleep(), Oracle DBMS_PIPE.RECEIVE_MESSAGE / DBMS_LOCK.SLEEP,
	// SQLite randomblob() burn loops. Listing only SLEEP/BENCHMARK/WAITFOR
	// left every non-MySQL backend undefended.
	sqliTimeDelay   = regexp.MustCompile(`(?i)\b(SLEEP\s*\(\s*\d+\s*\)|PG_SLEEP\s*\(|BENCHMARK\s*\(\s*\d+|WAITFOR\s+DELAY\s+['"]?\d+|DBMS_PIPE\.RECEIVE_MESSAGE\s*\(|DBMS_LOCK\.SLEEP\s*\(|RANDOMBLOB\s*\(\s*\d{6,})`)
	sqliCommentHack = regexp.MustCompile(`(?i)['"]\s*(--|#|/\*)`)
)

func checkSQLiCompact(input string) *WAFResult {
	if match := sqliUnionSelectCompact.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatSQLi,
			Severity:      SeverityCritical,
			Reason:        "SQL Injection detected: comment-fragmented UNION SELECT construct",
			MatchedRule:   "sqli_union_select_fragmented",
			MatchedSample: truncateSample(match, 50),
		}
	}
	return checkSQLi(input)
}

func checkSQLi(input string) *WAFResult {
	if len(input) == 0 {
		return nil
	}
	// Every rule below requires at least one of these lexical anchors. This
	// linear prefilter avoids running the full regex set over large inert
	// values (the Round-3 5 KB digit probe), while preserving every rule's
	// candidate language.
	hasUnion := containsASCIIFold(input, "UNION")
	if !hasUnion && !strings.ContainsAny(input, "=<>;#(") &&
		!strings.Contains(input, "--") && !strings.Contains(input, "/*") {
		return nil
	}
	booleanCandidate := strings.ContainsAny(input, "=<>") &&
		(containsASCIIWordFold(input, "OR") || containsASCIIWordFold(input, "AND"))
	if !strings.ContainsAny(input, ";#") &&
		!hasUnion &&
		!booleanCandidate &&
		!containsASCIIFold(input, " LIKE ") &&
		!containsASCIIFold(input, " IN ") &&
		!containsASCIIFold(input, "SLEEP") &&
		!containsASCIIFold(input, "BENCHMARK") &&
		!containsASCIIFold(input, "WAITFOR") &&
		!containsASCIIFold(input, "DBMS_") &&
		!containsASCIIFold(input, "RANDOMBLOB") &&
		!strings.Contains(input, "--") &&
		!strings.Contains(input, "/*") {
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
