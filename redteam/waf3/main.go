package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"noject/internal/waf"
)

type Atk struct {
	Name    string
	Path    string
	Query   string
	Body    string
	Headers map[string]string
	Why     string
}

func main() {
	engine := waf.NewEngine(waf.DefaultConfig())

	atks := []Atk{
		// ===== 1. CHARSET / ENCODING CONFUSION =====
		{"CHR: UTF-7 XSS", "/t", "q=+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "", nil,
			"Go's url.QueryUnescape leaves +ADw- as-is; IE historically decoded UTF-7; no charset handling in WAF"},
		{"CHR: UTF-16BE percent-encoded", "/t", "q=" + percEncodeUTF16BE("<script>alert(1)</script>"), "", nil,
			"payload encoded as UTF-16BE then percent-encoded; Go decodes %XX as raw bytes → UTF-16 gibberish to ASCII regex"},
		{"CHR: UTF-16LE percent-encoded", "/t", "q=" + percEncodeUTF16LE("<script>alert(1)</script>"), "", nil,
			"same trick little-endian"},
		{"CHR: overlong slash traversal", "/t", "f=..%c0%af..%c0%afetc/passwd", "", nil,
			"overlong UTF-8 '/' = %c0%af; QueryUnescape yields bytes c0 af — pathTraversalDot wants literal / %2f %5c"},
		{"CHR: overlong backslash", "/t", "f=..%c0%5c..%c0%5cwindows", "", nil,
			"overlong backslash variant"},
		{"CHR: invalid UTF-8 in query", "/t", "q=%ff%fe' OR '1'='1", "", nil,
			"Go keeps invalid bytes; SQLi regex still matches ASCII portion — control (should BLOCK)"},

		// ===== 2. HTTP PARAMETER POLLUTION (HPP) =====
		// Inspect scans the whole RawQuery string, so HPP within one query string is
		// all visible — but split the attack ACROSS param boundaries so neither half matches.
		{"HPP: split UNION across params", "/t", "a=UN&b=ION SE&c=LECT null--", "", nil,
			"raw query = 'a=UN&b=ION SE&c=LECT null--' — 'ION SE' has ' SE' between; UNION\\s+SELECT broken by &"},
		{"HPP: attack spans param boundary", "/t", "q=uni&x=on s&z=elect 1,2--", "", nil,
			"UNION SELECT assembled across & boundaries after URL parse, but WAF sees raw with &"},
		{"HPP: duplicate param shadow", "/t", "safe=hello&safe=' OR '1'='1", "", nil,
			"second param value IS visible in raw string — control, should block"},

		// ===== 3. SQL COMMENT-SPLITTING ADVANCED (keyword never reassembles) =====
		{"SQLi3: UN/**/ION SE/**/LECT + version", "/t", "q=1' UN/**/ION SE/**/LECT null,null--", "", nil,
			"normalize turns /**/ into space: UN ION SE LECT — 4 fragments, no UNION SELECT"},
		{"SQLi3: /*!UNION*/ /*!SELECT*/ split", "/t", "q=1' /*!UNION*/ /*!SELECT*/ null--", "", nil,
			"versioned unwrap inserts spaces around content: ' UNION ' ' SELECT ' — spaces BETWEEN tokens rejoin? no: 'UNION  SELECT' has 2 spaces — UNION\\s+SELECT matches multi-space. control check"},
		{"SQLi3: comment mid-keyword single", "/t", "q=1' UNI/**/ON SELECT null--", "", nil,
			"UNI ON SELECT — UNION keyword broken"},
		{"SQLi3: hash comment mid-value", "/t", "q=1' OR '1'='1' #", "", nil,
			"sqliCommentHack ['\"]\\s*(--|#|/\\*) — quote+# matches. control"},
		{"SQLi3: OR between identifiers", "/t", "q=1' OR x=x--", "", nil,
			"['\"] x [=] x — [a-zA-Z0-9]+ matches x; should BLOCK via boolean"},
		{"SQLi3: OR with parens", "/t", "q=1' OR (1)=(1)--", "", nil,
			"rhs ['\"]?[a-zA-Z0-9]+ — starts with '(' → no match on boolean rule; comment hack catches '-- after quote? quote before ( — sqliCommentHack needs ['\"] then (--|#|/*) — here '-- follows ')' not quote → BYPASS EXPECTED"},

		// ===== 4. NULL-BYTE / CONTROL-CHAR FRAGMENTATION =====
		{"NUL: NUL in UNION", "/t", "q=UN\x00ION SELECT null--", "", nil,
			"NUL never stripped in normalizeInput; regex sees UN<0>ION — no match"},
		{"NUL: NUL in script", "/t", "q=<s\x00cript>alert(1)</s\x00cript>", "", nil,
			"same for XSS script tag"},
		{"NUL: CR in script keyword", "/t", "q=<scr\ript>alert(1)</script>", "", nil,
			"<\\s*script requires contiguous 'script'; CR splits it"},
		{"NUL: tab inside UNION keyword", "/t", "q=UNI\tON SELECT null--", "", nil,
			"tab mid-keyword — UNION broken"},

		// ===== 5. SEMANTIC SQLi EVASION (dialect functions) =====
		{"SQLi3: MSSQL WAITFOR", "/t", "q=1'; WAITFOR DELAY '0:0:5'--", "", nil,
			"WAITFOR DELAY in sqliTimeDelay — control should block"},
		{"SQLi3: pg_sleep fractional", "/t", "q=1; SELECT pg_sleep(0.5)--", "", nil,
			"R1 confirmed slip; re-verify"},
		{"SQLi3: MySQL INTO OUTFILE", "/t", "q=1' UNION SELECT password INTO OUTFILE '/tmp/x'--", "", nil,
			"UNION SELECT matches first — blocked (control)"},
		{"SQLi3: LOAD_FILE standalone", "/t", "q=1' AND 1=LOAD_FILE('/etc/passwd')--", "", nil,
			"AND + function, no rule hits AND"},

		// ===== 6. HTML/DOM CLOBBERING-STYLE XSS =====
		{"XSS3: srcdoc on iframe", "/t", "q=<iframe srcdoc=<script>alert(1)</script>>", "", nil,
			"iframe tag caught by xssDangerousTags — control"},
		{"XSS3: form action javascript", "/t", "q=<form action=javascript:alert(1)><input type=submit></form>", "", nil,
			"javascript: URI rule catches it regardless of tag — control"},
		{"XSS3: details ontoggle", "/t", "q=<details open ontoggle=alert(1)>", "", nil,
			"on* handler rule — control"},
		{"XSS3: entity-encoded equals", "/t", "q=<img src=x onerror&#61;alert(1)>", "", nil,
			"&#61; → '=' after html.UnescapeString → onerror= → BLOCKED by event handler rule"},
		{"XSS3: backtick attr separator", "/t", "q=<img src=x `onerror`=`alert(1)`>", "", nil,
			"backtick not in [\\s/] and on* needs =; backticks around = — bypass for legacy IE"},
		{"XSS3: data:text/html full", "/t", "q=<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">click</a>", "", nil,
			"data: URI — no rule matches data: scheme; only javascript:"},
		{"XSS3: vbscript URI", "/t", "q=<a href=\"vbscript:msgbox(1)\">x</a>", "", nil,
			"vbscript: URI scheme never in rules (legacy IE)"},

		// ===== 7. ReDoS TIMING MEASUREMENTS =====
		{"REDOS3: boolean rule stress", "/t", "q=" + "'" + strings.Repeat("0", 5000), "", nil,
			"long digit run into sqliBooleanTrue"},
	}

	fmt.Printf("\n%-50s | %-7s | %-26s | %s\n", "ATTACK", "VERDICT", "RULE", "WHY")
	fmt.Println(strings.Repeat("-", 145))

	var bypasses []Atk
	for _, a := range atks {
		hdr := http.Header{"User-Agent": []string{"RedTeam/3.0"}}
		for k, v := range a.Headers {
			hdr.Set(k, v)
		}
		t0 := time.Now()
		res := engine.Inspect(http.MethodPost, a.Path, a.Query, hdr, []byte(a.Body))
		el := time.Since(t0)
		verdict, rule := "BYPASS", "-"
		if res != nil && res.Blocked {
			verdict, rule = "BLOCKED", res.MatchedRule
		} else if strings.HasPrefix(a.Name, "REDOS3:") && el <= 5*time.Millisecond {
			// This probe is benign input intended to measure algorithmic
			// complexity, not a payload that should be blocked. Passing means
			// bounded latency; treating every allowed timing probe as a bypass
			// inflated the security-bypass count by one.
			verdict, rule = "PASS", "bounded_latency"
		}
		if verdict == "BYPASS" {
			bypasses = append(bypasses, a)
		}
		lat := ""
		if el > 500*time.Microsecond {
			lat = fmt.Sprintf(" [%v SLOW]", el.Round(time.Microsecond))
		}
		fmt.Printf("%-50s | %-7s | %-26s | %s%s\n", trunc(a.Name, 50), verdict, trunc(rule, 26), trunc(a.Why, 58), lat)
	}

	fmt.Println(strings.Repeat("-", 145))
	fmt.Printf("TOTAL %d | BYPASSED %d | blocked %d\n\n", len(atks), len(bypasses), len(atks)-len(bypasses))
	for _, b := range bypasses {
		fmt.Printf("[BYPASS] %s\n  query=%q\n  why: %s\n\n", b.Name, b.Query, b.Why)
	}
}

func percEncodeUTF16BE(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(fmt.Sprintf("%%%02X%%%02X", byte(r>>8), byte(r)))
	}
	return b.String()
}

func percEncodeUTF16LE(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(fmt.Sprintf("%%%02X%%%02X", byte(r), byte(r>>8)))
	}
	return b.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
