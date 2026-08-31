package waf

import (
	"regexp"
)

var (
	cmdSubshell = regexp.MustCompile(`(\$\([^)]+\)|` + "`" + `[^` + "`" + `]+` + "`" + `)`)
	// Widened from a handful of named commands to a broad set of
	// interpreters/recon/exfil binaries. Still fundamentally a command
	// allowlist (any binary not listed here still slips through), but
	// scope is now query/path/headers only (see waf.go Inspect) where
	// legitimate content essentially never contains "; <word>" — so the
	// list can be broad without the false-positive cost body scanning had.
	cmdPipeOrChain = regexp.MustCompile(`(?i)(;|\||&&)\s*(cat\s+/etc/passwd|/bin/(sh|bash|zsh|dash)|curl\s+https?://|wget\s+https?://|rm\s+-rf|powershell|cmd\.exe|id\b|whoami\b|uname\b|nc\b|ncat\b|netcat\b|python[23]?\b|perl\b|ruby\b|nohup\b|chmod\b|chown\b|kill\b|pkill\b|base64\s+(-d|--decode)\b)`)
	cmdSystemPaths = regexp.MustCompile(`(?i)(/bin/(sh|bash|zsh|dash)|/usr/bin/id|/etc/shadow|/etc/passwd|c:\\windows\\system32)`)
	// Decode-then-execute is a classic signature-WAF-evasion primitive
	// (encode the real payload, decode it server-side, pipe to a shell) —
	// flag the pattern itself regardless of what the encoded payload says.
	cmdDecodeExecPipe = regexp.MustCompile(`(?i)base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh|python[23]?|perl|ruby)\b`)
	pathTraversalDot  = regexp.MustCompile(`(\.\./|\.\.\\|\.\.%2f|\.\.%5c)`)
)

func checkCommandInjection(input string) *WAFResult {
	if len(input) == 0 {
		return nil
	}

	if match := cmdSubshell.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatCMDInjection,
			Severity:      SeverityCritical,
			Reason:        "Command Injection detected: Subshell execution syntax $(...) or `...`",
			MatchedRule:   "cmd_subshell_syntax",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := cmdPipeOrChain.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatCMDInjection,
			Severity:      SeverityCritical,
			Reason:        "Command Injection detected: Piped or chained OS shell commands",
			MatchedRule:   "cmd_pipe_or_chain",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := cmdSystemPaths.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatCMDInjection,
			Severity:      SeverityHigh,
			Reason:        "Command Injection detected: Sensitive system binary/file invocation",
			MatchedRule:   "cmd_system_path_reference",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := cmdDecodeExecPipe.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatCMDInjection,
			Severity:      SeverityCritical,
			Reason:        "Command Injection detected: encoded payload decoded and piped to an interpreter",
			MatchedRule:   "cmd_decode_exec_pipe",
			MatchedSample: truncateSample(match, 50),
		}
	}

	return nil
}

func checkPathTraversal(input string) *WAFResult {
	if len(input) == 0 {
		return nil
	}

	if match := pathTraversalDot.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatPathTraversal,
			Severity:      SeverityHigh,
			Reason:        "Path Traversal detected: Directory traversal sequence (../)",
			MatchedRule:   "path_traversal_dot_dot",
			MatchedSample: truncateSample(match, 50),
		}
	}

	return nil
}
