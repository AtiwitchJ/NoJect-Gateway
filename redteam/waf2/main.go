package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"noject/internal/waf"
)

type Atk struct {
	Name    string
	Path    string // sent as URL path
	Query   string
	Body    string
	Headers map[string]string
	Why     string
}

func main() {
	engine := waf.NewEngine(waf.DefaultConfig())

	atks := []Atk{
		// ===== PATH-BASED INJECTION (WAF Inspect receives path, but proxy.go step-3
		// only passes r.URL.Path — and the early traversal check only fires on "..").
		// SQLi/XSS/CMD in the PATH itself is NEVER inspected on REST routes. =====
		{"PATH-INJ: SQLi in path segment", "/api/users' OR '1'='1", "", "", nil,
			"proxy step-3 calls Inspect(..., path=r.URL.Path) — path IS scanned, but checkSQLi runs on normQuery/normBody only! Path never hits SQLi check."},
		{"PATH-INJ: XSS in path", "/api/<script>alert(1)</script>", "", "", nil,
			"same — checkXSS runs on query/body/headers only, path excluded"},
		{"PATH-INJ: CMD in path", "/api/ping/127.0.0.1;id", "", "", nil,
			"checkCommandInjection on query/body/headers — path excluded"},
		{"PATH-INJ: encoded SQLi in path", "/api/users%27%20OR%20%271%27%3D%271", "", "", nil,
			"encoded form also skipped since path never inspected"},

		// ===== HEADER SURFACE (only Referer/User-Agent/X-Forwarded-For scanned) =====
		{"HDR-INJ: Cookie header SQLi", "/api/users", "", "", map[string]string{"Cookie": "session=' OR '1'='1--"},
			"scannedHeaders = [Referer, UA, XFF] — Cookie is attacker-controlled and commonly logged/reflected"},
		{"HDR-INJ: Authorization SQLi", "/api/users", "", "", map[string]string{"Authorization": "Bearer ' UNION SELECT password--"},
			"Authorization not scanned"},
		{"HDR-INJ: X-Custom header XSS", "/api/users", "", "", map[string]string{"X-Custom-Header": "<script>alert(1)</script>"},
			"arbitrary custom headers not scanned"},
		{"HDR-INJ: X-Forwarded-Host traversal", "/api/users", "", "", map[string]string{"X-Forwarded-Host": "../../etc/passwd"},
			"XFH not in scannedHeaders"},

		// ===== ADVANCED SQLi =====
		{"SQLi: MySQL comment splitting keyword", "/api/t", "id=UN/**/ION SE/**/LECT null--", "", nil,
			"normalizeInput collapses /**/ to SPACE: 'UN ION SE LECT' — keywords SPLIT, never rejoin"},
		{"SQLi: versioned comment split", "/api/t", "id=UN/*!ION*/SEL/*!ECT*/null--", "", nil,
			"unwrap yields 'UN ION SEL ECT' — same class of split, versioned form"},
		{"SQLi: tab/newline inside UNION SELECT", "/api/t", "id=1' UNION\tSELECT\tnull--", "", nil,
			"\\s+ matches tab — should block (control)"},
		{"SQLi: AND boolean no comment", "/api/t", "id=1' AND '1'='1", "", nil,
			"no OR anchor — known gap, confirm via query surface"},
		{"SQLi: HAVING clause", "/api/t", "id=1' HAVING 1=1--", "", nil,
			"HAVING rule absent entirely"},
		{"SQLi: ORDER BY exfil", "/api/t", "id=1' ORDER BY (SELECT password FROM users LIMIT 1)--", "", nil,
			"nested SELECT without UNION"},
		{"SQLi: EXTRACTVALUE error-based", "/api/t", "id=1' AND EXTRACTVALUE(1,concat(0x7e,version()))--", "", nil,
			"AND + function — no rule hits"},
		{"SQLi: double-encoded quote then AND", "/api/t", "q=%2527%2520AND%2520%2527a%2527%253D%2527a", "", nil,
			"after 2 passes: ' AND 'a'='a — AND form still unmatched"},
		{"SQLi: JSON body nested", "/api/t", "", `{"filter":{"$where":"1' OR '1'='1"}}`, nil,
			"body inspected as raw string — value still contains quote so should block via body scan (control)"},

		// ===== ADVANCED XSS =====
		{"XSS: polyglot", "/api/t", "q=javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>", "", nil,
			"Gareth Heyes polyglot — matches javascript: rule directly (control)"},
		{"XSS: SVG with encoded handler", "/api/t", "q=%3Csvg%20onload%3Dalert(1)%3E", "", nil,
			"URL-encoded — normalized, should block (control)"},
		{"XSS: double-encoded event handler", "/api/t", "q=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E", "", nil,
			"2-pass decode → <img src=x onerror=alert(1)> — should block after normalization"},
		{"XSS: triple-encoded", "/api/t", "q=%25253Cscript%25253Ealert(1)%25253C/script%25253E", "", nil,
			"3-pass: %25253C→%253C→%3C→< — 5-pass loop handles it"},
		{"XSS: HTML entity inside script keyword", "/api/t", "q=&lt;script&gt;alert(1)&lt;/script&gt;", "", nil,
			"html.UnescapeString → <script> — blocked"},
		{"XSS: mixed entity+URL double", "/api/t", "q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B", "", nil,
			"%26lt%3B → &lt; → < — both unescape layers"},

		// ===== ADVANCED CMD =====
		{"CMD: ${PATH} expansion", "/api/t", "h=127.0.0.1;${PATH}", "", nil,
			"cmdIFSObfuscation misses ${PATH}; cmdPipeOrChain needs listed cmd after ;"},
		{"CMD: command via variable deref", "/api/t", "h=127.0.0.1;$0 -c id", "", nil,
			"$0 is sh itself; $ not in alternation set"},
		{"CMD: windows %COMSPEC%", "/api/t", "h=127.0.0.1 & %COMSPEC% /c dir", "", nil,
			"lone & + env var"},
		{"CMD: process substitution <()", "/api/t", "h=127.0.0.1;diff <(ls) <(ls)", "", nil,
			"<() subshell form not in cmdSubshell (only $(...) and backticks)"},
		{"CMD: here-string <<<", "/api/t", "h=x;cat<<<$(id)", "", nil,
			"$() nested inside <<< still caught by cmdSubshell inner match (control)"},
		{"CMD: CRLF separator", "/api/t", "h=127.0.0.1%0A%0Aid", "", nil,
			"%0A decodes to newline — same newline-separator gap, URL-delivered"},
		{"CMD: semicolon in JSON body field", "/api/t", "", `{"host":"127.0.0.1;sleep 10"}`, nil,
			"body IS scanned for CMD — sleep not in allowlist → bypass via body too"},

		// ===== ReDoS probe (timing measured outside) =====
		{"REDOS: sqliBooleanTrue catastrophic", "/api/t", "q=" + "'" + strings.Repeat(" OR 'a", 40), "", nil,
			"nested quantifiers in ([a-zA-Z0-9]+...)+ — measure inspect latency"},

		// ===== Path traversal via RawPath trick =====
		{"TRV: URL.RawPath divergence", "/%2e%2e%2fetc%2fpasswd", "", "", nil,
			"Go sets RawPath=/..., Path=/../../etc/passwd? depends on parse; early check looks at RequestURI only for '..'"},
	}

	fmt.Printf("\n%-52s | %-7s | %-28s | %s\n", "ATTACK", "VERDICT", "RULE", "WHY")
	fmt.Println(strings.Repeat("-", 150))

	var bypasses []Atk
	for _, a := range atks {
		hdr := http.Header{"User-Agent": []string{"Mozilla/5.0 RedTeam/2.0"}}
		for k, v := range a.Headers {
			hdr.Set(k, v)
		}
		// query sent raw (not pre-escaped) — Inspect normalizes internally
		res := engine.Inspect(http.MethodPost, a.Path, a.Query, hdr, []byte(a.Body))
		verdict, rule := "BYPASS", "-"
		if res != nil && res.Blocked {
			verdict, rule = "BLOCKED", res.MatchedRule
		}
		if verdict == "BYPASS" {
			bypasses = append(bypasses, a)
		}
		fmt.Printf("%-52s | %-7s | %-28s | %s\n", trunc(a.Name, 52), verdict, trunc(rule, 28), trunc(a.Why, 55))
	}

	fmt.Println(strings.Repeat("-", 150))
	fmt.Printf("TOTAL: %d attacks | BYPASSED %d | blocked %d\n\n", len(atks), len(bypasses), len(atks)-len(bypasses))
	for _, b := range bypasses {
		fmt.Printf("[BYPASS] %s\n  path=%q query=%q\n  headers=%v\n  why: %s\n\n", b.Name, b.Path, b.Query, b.Headers, b.Why)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var _ = url.QueryEscape // keep import
