package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"noject/internal/waf"
)

type Attack struct {
	Name     string
	Payload  string // sent as query + body
	Category string
	Why      string // exploitation rationale
}

func main() {
	engine := waf.NewEngine(waf.DefaultConfig())

	attacks := []Attack{
		// ---- SQLi evasion (sqli.go regex gaps) ----
		{"SQLi: unquoted tautology trailing comment", "' OR 1=1 --", "SQLi",
			"sqliBooleanTrue requires quotes around the rhs comparison (['\"][a-zA-Z0-9]+); unquoted digits only match the OR 1=1(--|#) alt which needs the comment abutting the digit"},
		{"SQLi: digit RHS quoted comparison", "' OR 'abc' = 'abc", "SQLi",
			"rhs term [a-zA-Z0-9]+ matches abc; tests quote imbalance handling"},
		{"SQLi: unquoted RHS LIKE/IN alt digit", "' OR name LIKE 'ad", "SQLi",
			"LIKE alt requires (=|<>|!=|>|<|LIKE|IN) then ['(]?[a-zA-Z0-9]+ — ok"},
		{"SQLi: pg_sleep time-based (PostgreSQL)", "1; SELECT pg_sleep(5)--", "SQLi",
			"sqliTimeDelay only knows SLEEP/BENCHMARK/WAITFOR; pg_sleep slips"},
		{"SQLi: MySQL SLEEP without quote+comment", "admin' AND SLEEP(5) AND '1'='1", "SQLi",
			"SLEEP(5) matches sqliTimeDelay directly — control case"},
		{"SQLi: boolean SUBSTRING blind", "' AND SUBSTRING(version(),1,1)='5'--", "SQLi",
			"sqliTimeDelay misses SUBSTRING; comment hack matches quote+--  at the end"},
		{"SQLi: no-space UNION via comments", "1' UNION/**/SELECT/**/null,version()--", "SQLi",
			"normalizeInput collapses /**/ to space — should reconstruct UNION SELECT"},
		{"SQLi: versioned comment wrapping payload", "1' /*!50000UNION*/ /*!50000SELECT*/ password FROM users--", "SQLi",
			"sqlVersionedComment unwraps /*!...*/ to inner content; UNION SELECT reformats"},
		{"SQLi: double-encoded UNION SELECT", "%2527%2520UNION%2520SELECT%2520null--", "SQLi",
			"normalize loops QueryUnescape 5x to fixed point; %25->%' then decode again"},
		{"SQLi: INSERT..SELECT exfil (no UNION)", "'; INSERT INTO logs SELECT password FROM users--", "SQLi",
			"sqliStacked covers ;INSERT INTO — should block"},
		{"SQLi: UPDATE without SET gap", ";UPDATE users SET role=0x61646d696e", "SQLi",
			"sqliStacked UPDATE\\s+\\w+\\s+SET — matches"},
		{"SQLi: AND-based tautology (not OR)", "admin' AND '1'='1", "SQLi",
			"sqliBooleanTrue only anchors on OR; ' AND 'x'='x has no rule -> BYPASS EXPECTED"},
		{"SQLi: OR with function comparing", "' OR LENGTH(database())>0--", "SQLi",
			"rhs must be ['\"]?[a-zA-Z0-9]+[=<>...]; LENGTH(...) contains '(' — the IN list needs ['(]? ; after [a-zA-Z0-9]+ we have LENGTH then (, allowed by ['(]?  but then >0 -- follows; 1=1-style tail missing -> test"},
		{"SQLi: case/whitespace mix in UNION", "uNiOn\nSeLeCt null,null--", "SQLi",
			"\\s+ in UNION (ALL )?SELECT matches newline — should block"},
		{"SQLi: second-order encoded quote", "%2527%2520OR%25201%253D1", "SQLi",
			"double-decode leaves ' OR 1=1 unquoted — same gap as case 1, then with no trailing comment -> BYPASS EXPECTED"},

		// ---- XSS evasion (xss.go regex gaps) ----
		{"XSS: svg onload with slash separator", "<svg/onload=alert(1)>", "XSS",
			`xssEventHandler allows [\s/] before on* — blocked by design; control`},
		{"XSS: data: URI in iframe", "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></iframe>", "XSS",
			"xssDangerousTags blocks <iframe regardless of src — blocked"},
		{"XSS: scrİpt with unicode lookalike", "<scrıpt>alert(1)</scrıpt>", "XSS",
			"Turkish dotless ı (U+0131) evades literal 'script' ASCII match — no unicode folding in Go regexp by default"},
		{"XSS: null-byte inside script tag", "<scr\x00ipt>alert(1)</scr\x00ipt>", "XSS",
			"browsers strip NUL before tag parsing (per HTML spec); regex sees scr\\x00ipt — no match"},
		{"XSS: newline inside tag name", "<scr\nipt>alert(1)</scr\nipt>", "XSS",
			"browser treats as script? Actually <scr newline ipt is not valid; but <script\\t> is. Try tab variant"},
		{"XSS: form feed inside tag", "<script\x0C>alert(1)</script>", "XSS",
			"[^>]* matches \\x0C fine; <script[^>]*> blocked"},
		{"XSS: svg onload with newline separator", "<svg\nonload=alert(1)>", "XSS",
			`[\s/] matches \n — blocked`},
		{"XSS: image onerror with uppercase handler", "<IMG SRC=x OnErRoR=alert(1)>", "XSS",
			"(?i) applied — blocked"},
		{"XSS: HTML entity encoded javascript URI", "&Tab;javascript:alert(1)", "XSS",
			"html.UnescapeString -> \tjavascript:; xssJavascriptURI \\bjavascript — \\t is a word boundary -> blocked"},
		{"XSS: mixed-case + whitespace javascript URI", "jAva\nScRiPt:alert(1)", "XSS",
			"regex \\bjavascript\\s*: — allows whitespace only around ':', not inside token -> BYPASS EXPECTED if browser tolerates? (browser does NOT tolerate newline inside scheme; control for negative)"},
		{"XSS: attribute with backtick separator", "<img src=x `onerror=alert(1)>", "XSS",
			"IE tolerated backticks; [\\s/] misses ` -> may bypass Go regex; browser-compat limited"},
		{"XSS: onfocus without quoted value, no <>", "x onfocus=alert(1) autofocus", "XSS",
			"xssEventHandler requires '<...[\\s/]on...' — without leading < no match; if reflected into existing tag context, dangerous"},

		// ---- CMD injection evasion (cmd_injection.go) ----
		{"CMD: ;ls after IP (allowlist gap)", "127.0.0.1; ls -la /", "CMD",
			"cmdPipeOrChain names ~35 binaries; ls is NOT in the alternation -> BYPASS EXPECTED"},
		{"CMD: ;touch after IP (allowlist gap)", "127.0.0.1; touch /tmp/pwned", "CMD",
			"touch not in alternation -> BYPASS EXPECTED"},
		{"CMD: ;sleep (recon timing)", "127.0.0.1; sleep 5", "CMD",
			"sleep not in alternation -> BYPASS EXPECTED"},
		{"CMD: || (OR pipe) instead of |", "127.0.0.1 || whoami", "CMD",
			"alternation anchors on (;|\\||&&) — single | in || matches first | -> whoami in list -> blocked"},
		{"CMD: $IFS obfuscation (control)", "127.0.0.1;cat$IFS/etc$IFS/passwd", "CMD",
			"cmdIFSObfuscation catches $IFS -> blocked"},
		{"CMD: globbed binary path (control)", "127.0.0.1; /?in/?at /etc/?asswd", "CMD",
			"cmdGlobbedPath matches /(bin)/c?t etc — /?in/ starts with ?; (bin|usr|etc..) requires literal dir name — /?in/ bypasses -> BYPASS EXPECTED"},
		{"CMD: backtick subshell (control)", "127.0.0.1 `id`", "CMD",
			"cmdSubshell matches `id` -> blocked"},
		{"CMD: $() subshell nested", "127.0.0.1 $(echo $(id))", "CMD",
			"cmdSubshell \\$\\([^)]+\\) non-greedy single depth; $(echo $(id)) -> first ) closes after id; outer $( still matched partially? regex matches innermost too -> blocked"},
		{"CMD: newline as separator", "127.0.0.1\nid", "CMD",
			"POSIX sh treats \\n as command separator; regex only knows ; | && -> BYPASS EXPECTED"},
		{"CMD: & background separator", "127.0.0.1 & id", "CMD",
			"single & is a valid separator in sh; alternation has && or | or ; but NOT lone & -> test"},
		{"CMD: 0x hex IP obfuscation", "0x7f000001; id", "CMD",
			"target IP representation irrelevant; ;id suffix still matches (id\\b in list)"},
		{"CMD: windows cmd /c", "127.0.0.1 & cmd /c dir", "CMD",
			"cmd\\.exe in list but plain 'cmd /c' not; lone & not matched -> BYPASS EXPECTED on Windows deployments"},
		{"CMD: env var expansion", "127.0.0.1; ${HOME}", "CMD",
			"; ${HOME}: cmdPipeOrChain needs a listed command after ; — ${HOME} is none; cmdIFSObfuscation only matches $IFS variants -> BYPASS EXPECTED (low impact alone but enables exfil chains)"},

		// ---- Path traversal (waf.go normalizeInput + pathTraversalDot) ----
		{"PATH: mixed separators", "..\\../..\\../etc/passwd", "PATH",
			"pathTraversalDot has ../ and ..\\\\ — mixed .../../ matches the ../ half -> blocked"},
		{"PATH: overlong UTF-8 of dot", "%c0%ae%c0%ae/", "PATH",
			"url.QueryUnescape yields \\xc0\\xae (invalid UTF-8 but Go keeps bytes); pathTraversalDot looks for '.' — overlong encoding never contains literal '.' or %2e after decode? QueryUnescape('%c0%ae') -> bytes \\xc0\\xae, no '.' produced -> BYPASS EXPECTED (relevant if downstream decodes overlong UTF-8)"},
		{"PATH: unicode fullwidth dot", "‥/‥/etc/passwd", "PATH",
			"U+2025 TWO DOT LEADER is not '.' — pathTraversalDot literal ../../ only -> BYPASS EXPECTED if downstream filesystem treats U+2025 as dots (rare)"},
		{"PATH: nested %252e", "%252e%252e%252fetc%252fpasswd", "PATH",
			"double decode loop: %252e->%2e->. and %252f->%2f->/ after 2 passes -> blocked"},
		{"PATH: absolute /etc/passwd no dots", "/etc/passwd", "PATH",
			"LFI without traversal: reads file= param mapping to absolute path; pathTraversalDot only looks for ../ -> BYPASS EXPECTED"},
		{"PATH: /etc/passwd in body JSON", "{\"file\": \"/etc/passwd\"}", "PATH",
			"body is scanned for traversal but not absolute-path alone; absolute paths slip -> BYPASS EXPECTED"},
		{"PATH: php filter wrapper", "php://filter/convert.base64-encode/resource=/etc/passwd", "PATH",
			"no ../ present; wrappers are stream schemes — not matched -> BYPASS EXPECTED"},
		{"PATH: null byte poisoned", "../../etc/passwd%00.jpg", "PATH",
			"../ present -> blocked"},
	}

	headers := http.Header{"User-Agent": []string{"Mozilla/5.0 (compatible; RedTeam/1.0)"}}

	fmt.Printf("\n%-52s | %-7s | %-8s | %s\n", "ATTACK", "VERDICT", "RULE", "RATIONALE")
	fmt.Println(strings.Repeat("-", 130))

	bypasses := []Attack{}
	for _, a := range attacks {
		// Deliver payload through query + body (the surfaces the WAF inspects)
		res := engine.Inspect(http.MethodPost, "/api/chat", url.QueryEscape(a.Payload), headers, []byte(a.Payload))
		verdict := "BYPASS"
		rule := "-"
		if res != nil && res.Blocked {
			verdict = "BLOCKED"
			rule = res.MatchedRule
		}
		if verdict == "BYPASS" {
			bypasses = append(bypasses, a)
		}
		fmt.Printf("%-52s | %-7s | %-8s | %s\n", truncate(a.Name, 52), verdict, rule, truncate(a.Why, 60))
	}

	fmt.Println(strings.Repeat("-", 130))
	fmt.Printf("TOTAL: %d attacks, %d BYPASSED, %d blocked\n", len(attacks), len(bypasses), len(attacks)-len(bypasses))
	if len(bypasses) > 0 {
		fmt.Println("\n=== SUCCESSFUL EVASIONS (vulnerabilities) ===")
		for _, b := range bypasses {
			fmt.Printf("[%s] %s\n  payload: %s\n  why    : %s\n\n", b.Category, b.Name, b.Payload, b.Why)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
