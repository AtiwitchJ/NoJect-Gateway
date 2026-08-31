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
	// Separator class includes single "&" and raw newline/carriage-return —
	// both are command separators to a shell and were previously missing,
	// so "host & id" and "host\nid" walked straight through.
	cmdPipeOrChain = regexp.MustCompile(`(?i)(;|\||&|\r|\n)\s*(cat\s+/etc/passwd|/bin/(sh|bash|zsh|dash)|curl\s+https?://|wget\s+https?://|rm\s+-rf|powershell|cmd\.exe|id\b|whoami\b|uname\b|hostname\b|ls\b|pwd\b|cat\b|echo\b|sh\b|bash\b|zsh\b|nc\b|ncat\b|netcat\b|socat\b|python[23]?\b|perl\b|ruby\b|php\b|node\b|awk\b|gawk\b|sed\b|env\b|printenv\b|find\b|xargs\b|dd\b|tar\b|openssl\b|nohup\b|chmod\b|chown\b|kill\b|pkill\b|base64\s+(-d|--decode)\b)`)
	// Shell metacharacter obfuscation, independent of which binary is named.
	// The allowlist above is inherently incomplete — any interpreter not
	// enumerated slips through — so these rules target the *evasion
	// technique* instead of the command:
	//   - $IFS / ${IFS} as a space substitute (cat$IFS/etc$IFS/passwd)
	//   - brace/variable expansion used to assemble a command (${x}, $'..')
	//   - glob wildcards standing in for characters of a sensitive path
	//     (/bin/c?t, /etc/p*wd)
	cmdIFSObfuscation = regexp.MustCompile(`\$\{?IFS\}?`)
	cmdGlobbedPath    = regexp.MustCompile(`/(bin|usr|etc|sbin|var|tmp)/[A-Za-z0-9_.\-]*[?*\[][A-Za-z0-9_.\-?*\[\]]*`)
	// "cmd -exec" style secondary execution (find ... -exec sh, ... -execdir)
	cmdExecFlag    = regexp.MustCompile(`(?i)-exec(dir)?\s+`)
	cmdSystemPaths = regexp.MustCompile(`(?i)(/bin/(sh|bash|zsh|dash)|/usr/bin/id|/etc/shadow|/etc/passwd|c:\\windows\\system32)`)
	// Decode-then-execute is a classic signature-WAF-evasion primitive
	// (encode the real payload, decode it server-side, pipe to a shell) —
	// flag the pattern itself regardless of what the encoded payload says.
	cmdDecodeExecPipe = regexp.MustCompile(`(?i)base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh|python[23]?|perl|ruby)\b`)
	pathTraversalDot  = regexp.MustCompile(`(\.\./|\.\.\\|\.\.%2f|\.\.%5c)`)

	// cmdSeparatorThenCommand is the INVERTED rule: rather than naming the
	// binaries we consider dangerous, it flags the shell syntax itself —
	// a command separator followed by anything that looks like a command.
	//
	// A binary allowlist is unwinnable: every command not enumerated
	// ("; ls", "; env", "; busybox sh") walks straight through, and the
	// list can never be completed. Separators, by contrast, are the part
	// the attacker cannot omit.
	//
	// The command token must be followed by an actual shell-argument
	// indicator — a flag (-la), an absolute path (/etc/passwd), a redirect
	// (> <), a subshell, or another separator. Matching a bare word after a
	// separator is too loose for a query string: "title=Rock %26 Roll"
	// decodes to "Rock & Roll" and would be flagged as "& Roll".
	//
	// Bare invocations with no argument ("& id", "; whoami") are covered by
	// the named-binary rule above instead, which is the right trade: an
	// unknown binary needs shell syntax around it to be worth flagging,
	// while a known recon binary is suspicious on its own.
	//
	// Only safe on surfaces where shell metacharacters have no legitimate
	// use (URL path, query string, headers). Request bodies carry prose and
	// code where ";" and "|" are ordinary text — see
	// checkCommandInjectionStrict.
	cmdSeparatorThenCommand = regexp.MustCompile(`(?:;|\|\|?|&&?|\r|\n)\s*/?(?:[a-z0-9_.-]+/)*[a-z][a-z0-9_.-]*\s+(?:-{1,2}[a-z0-9]|/[a-z]|[<>]|\$\(|` + "`" + `)`)
)

// checkCommandInjectionStrict applies syntax-level command-injection
// detection in addition to the shared named-binary rules. Use it for URL
// path, query string, and headers — never for request bodies, where shell
// metacharacters appear in ordinary content.
func checkCommandInjectionStrict(input string) *WAFResult {
	if res := checkCommandInjection(input); res != nil {
		return res
	}
	if len(input) == 0 {
		return nil
	}
	if match := cmdSeparatorThenCommand.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatCMDInjection,
			Severity:      SeverityCritical,
			Reason:        "Command Injection detected: shell command separator followed by a command token",
			MatchedRule:   "cmd_separator_then_command",
			MatchedSample: truncateSample(match, 50),
		}
	}
	return nil
}

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

	if match := cmdIFSObfuscation.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatCMDInjection,
			Severity:      SeverityCritical,
			Reason:        "Command Injection detected: $IFS whitespace-substitution obfuscation",
			MatchedRule:   "cmd_ifs_obfuscation",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := cmdGlobbedPath.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatCMDInjection,
			Severity:      SeverityHigh,
			Reason:        "Command Injection detected: glob wildcard concealing a system path",
			MatchedRule:   "cmd_globbed_system_path",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := cmdExecFlag.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatCMDInjection,
			Severity:      SeverityCritical,
			Reason:        "Command Injection detected: secondary execution flag (-exec/-execdir)",
			MatchedRule:   "cmd_exec_flag",
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
