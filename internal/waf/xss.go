package waf

import (
	"regexp"
)

var (
	xssScriptTag = regexp.MustCompile(`(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>|<\s*script[^>]*>`)
	// Matches ANY on*="..." event-handler attribute (onload, onerror,
	// ontoggle, onwheel, ...), not an enumerated allowlist of handler
	// names — an allowlist here misses the majority of the ~150 DOM event
	// handlers browsers support. Separator is space OR "/", since HTML
	// tolerates "/" between attributes in self-closing-style tags
	// (<svg/onload=...> is valid and a well-known WAF-bypass technique
	// against handler regexes that require a literal space).
	xssEventHandler  = regexp.MustCompile(`(?i)<\s*[a-zA-Z0-9_-]+\b[^>]*[\s/]on[a-zA-Z]+\s*=`)
	xssJavascriptURI = regexp.MustCompile(`(?i)\bjavascript\s*:\s*[^\s]+`)
	xssDangerousTags = regexp.MustCompile(`(?i)<\s*(iframe|object|embed|applet|meta\s+http-equiv)\b[^>]*>`)
)

func checkXSS(input string) *WAFResult {
	if len(input) == 0 {
		return nil
	}

	if match := xssScriptTag.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatXSS,
			Severity:      SeverityHigh,
			Reason:        "XSS detected: SCRIPT tag injection",
			MatchedRule:   "xss_script_tag",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := xssEventHandler.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatXSS,
			Severity:      SeverityHigh,
			Reason:        "XSS detected: Inline event handler attribute (e.g. onerror/onload)",
			MatchedRule:   "xss_event_handler",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := xssJavascriptURI.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatXSS,
			Severity:      SeverityHigh,
			Reason:        "XSS detected: javascript: URI scheme",
			MatchedRule:   "xss_javascript_uri",
			MatchedSample: truncateSample(match, 50),
		}
	}

	if match := xssDangerousTags.FindString(input); match != "" {
		return &WAFResult{
			Blocked:       true,
			ThreatType:    ThreatXSS,
			Severity:      SeverityMedium,
			Reason:        "XSS detected: Dangerous embed/iframe tag injection",
			MatchedRule:   "xss_dangerous_tag",
			MatchedSample: truncateSample(match, 50),
		}
	}

	return nil
}
