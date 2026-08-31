package waf

import (
	"net/http"
	"testing"
)

// Benign traffic corpus.
//
// Detection rules are ratcheted tighter every time a red-team pass finds a
// bypass, and each tightening risks blocking real users. That failure is
// invisible to an attack-only corpus: blocking everything scores 100% there.
// A blocked customer is an outage, and a WAF that causes outages gets turned
// off — which is a worse security outcome than the bypass it prevented.
//
// This corpus exists so a rule change that breaks legitimate traffic fails
// CI immediately. It has already caught one real regression: a widened
// command-injection rule flagged "title=Rock %26 Roll" (decoding to
// "Rock & Roll") as a shell command.
//
// When adding a detection rule, add the benign counterpart here too.

func TestBenignQueryStrings(t *testing.T) {
	e := NewEngine(DefaultConfig())
	cases := []struct{ name, query string }{
		{"plain search", `q=hello world`},
		{"comparison filter", `filter=price>100&sort=name`},
		{"path-like value", `path=/api/v1/users`},
		{"encoded plus signs", `q=C%2B%2B programming`},
		{"list and paging", `ids=1,2,3&page=2`},
		{"repeated key", `tags=go&tags=rust`},
		{"absolute url value", `redirect=https://example.com/next`},
		{"email value", `email=a@b.com`},
		{"encoded ampersand in prose", `title=Rock %26 Roll`},
		{"ampersand in prose", `band=Simon & Garfunkel`},
		{"date range", `range=2024-01-01..2024-12-31`},
		{"sql keyword as content", `sql=SELECT name FROM docs`},
		{"boolean words", `search=AND OR NOT`},
		{"apostrophe in name", `name=O'Brien`},
		{"math expression", `q=what is 1=1 in math`},
		{"semicolon in prose", `note=first; then second`},
		{"pipe in table syntax", `md=col a | col b`},
		{"version string", `v=1.2.3`},
		{"uuid", `id=550e8400-e29b-41d4-a716-446655440000`},
		{"hyphenated words", `q=state-of-the-art design`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.Inspect(http.MethodGet, "/api/search", tc.query, http.Header{}, nil)
			if res.Blocked {
				t.Errorf("blocked benign query %q (rule=%s, sample=%q)",
					tc.query, res.MatchedRule, res.MatchedSample)
			}
		})
	}
}

func TestBenignRequestBodies(t *testing.T) {
	e := NewEngine(DefaultConfig())
	cases := []struct{ name, body string }{
		{"prose with shell words", `{"messages":[{"role":"user","content":"run ls; then cat the file"}]}`},
		{"code snippet", `{"code":"if (a && b) { return a|b; }"}`},
		{"pipe explanation", `{"text":"Use pipes: cmd1 | cmd2; done"}`},
		{"union as english word", `{"q":"union representative selection process"}`},
		{"sql tutorial content", `{"content":"SELECT * FROM users is a basic query"}`},
		{"markdown table", `{"md":"| name | value |\n|---|---|\n| a | 1 |"}`},
		{"file path discussion", `{"q":"where is /etc/hosts on macOS?"}`},
		{"regex question", `{"q":"what does the pattern a.*b match?"}`},
		{"json with numbers", `{"messages":[{"role":"user","content":"totals: 1, 2, 3"}]}`},
		{"html as escaped text", `{"content":"use &lt;div&gt; for a block element"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.Inspect(http.MethodPost, "/v1/chat/completions", "", http.Header{}, []byte(tc.body))
			if res.Blocked {
				t.Errorf("blocked benign body %q (rule=%s, sample=%q)",
					tc.body, res.MatchedRule, res.MatchedSample)
			}
		})
	}
}

// Headers were brought into scope for SQLi/XSS/command scanning, which put
// real JWTs, session cookies and browser user-agents in the blast radius.
func TestBenignHeaders(t *testing.T) {
	e := NewEngine(DefaultConfig())
	cases := []struct{ name, key, value string }{
		{"jwt bearer", "Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{"basic auth", "Authorization", "Basic dXNlcjpwYXNzd29yZA=="},
		{"api key header", "Authorization", "ApiKey sk-noject-demo-client-key"},
		{"session cookies", "Cookie", "sessionid=abc123def456; csrftoken=xyz789; theme=dark"},
		{"analytics cookies", "Cookie", "_ga=GA1.2.1234567890.1234567890; _gid=GA1.2.987654321.1234567890"},
		{"url-encoded json cookie", "Cookie", "cart=%7B%22items%22%3A%5B1%2C2%5D%7D"},
		{"chrome user agent", "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
		{"curl user agent", "User-Agent", "curl/8.4.0"},
		{"bot user agent", "User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
		{"referer with query", "Referer", "https://example.com/search?q=union+representative&sort=name"},
		{"referer with hyphens", "Referer", "https://example.com/docs/select-from-list"},
		{"origin", "Origin", "https://app.example.com"},
		{"proxy chain", "X-Forwarded-For", "203.0.113.7, 198.51.100.2"},
		{"api key value", "X-Api-Key", "sk-noject-demo-client-key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(tc.key, tc.value)
			res := e.Inspect(http.MethodGet, "/api/x", "", h, nil)
			if res.Blocked {
				t.Errorf("blocked benign %s header %q (rule=%s, sample=%q)",
					tc.key, tc.value, res.MatchedRule, res.MatchedSample)
			}
		})
	}
}

func TestBenignPaths(t *testing.T) {
	e := NewEngine(DefaultConfig())
	cases := []string{
		"/api/v1/users/42",
		"/v1/chat/completions",
		"/files/report-2024-Q1.pdf",
		"/docs/getting-started",
		"/api/orders/550e8400-e29b-41d4-a716-446655440000",
		"/search/state-of-the-art",
		"/i18n/th-TH/messages",
		"/static/app.min.js",
	}

	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			res := e.Inspect(http.MethodGet, path, "", http.Header{}, nil)
			if res.Blocked {
				t.Errorf("blocked benign path %q (rule=%s, sample=%q)",
					path, res.MatchedRule, res.MatchedSample)
			}
		})
	}
}
