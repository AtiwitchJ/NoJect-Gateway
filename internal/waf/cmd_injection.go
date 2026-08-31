package waf

import (
	"regexp"
)

var (
	cmdSubshell      = regexp.MustCompile(`(\$\([^)]+\)|` + "`" + `[^` + "`" + `]+` + "`" + `)`)
	cmdPipeOrChain   = regexp.MustCompile(`(?i)(;|\||&&)\s*(cat\s+/etc/passwd|/bin/sh|/bin/bash|curl\s+https?://|wget\s+https?://|rm\s+-rf|powershell|cmd\.exe)`)
	cmdSystemPaths   = regexp.MustCompile(`(?i)(/bin/(sh|bash|zsh|dash)|/usr/bin/id|/etc/shadow|/etc/passwd|c:\\windows\\system32)`)
	pathTraversalDot = regexp.MustCompile(`(\.\./|\.\.\\|\.\.%2f|\.\.%5c)`)
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
