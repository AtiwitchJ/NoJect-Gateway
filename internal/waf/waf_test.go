package waf

import (
	"net/http"
	"testing"
)

func TestFastPathWAF(t *testing.T) {
	engine := NewEngine(Config{
		EnableSQLi:         true,
		EnableXSS:          true,
		EnableCMDInjection: true,
		EnablePathTraversal: true,
	})

	testCases := []struct {
		name          string
		method        string
		path          string
		query         string
		headers       http.Header
		body          []byte
		expectBlocked bool
		expectThreat  ThreatType
	}{
		// Clean / Legitimate requests (False Positive tests)
		{
			name:          "Clean GET request",
			method:        http.MethodGet,
			path:          "/api/v1/users",
			query:         "page=1&limit=20&search=john_doe",
			expectBlocked: false,
			expectThreat:  ThreatNone,
		},
		{
			name:          "Clean JSON LLM chat prompt",
			method:        http.MethodPost,
			path:          "/v1/chat/completions",
			body:          []byte(`{"messages":[{"role":"user","content":"How do I select the best union representative for my workers?"}]}`),
			expectBlocked: false,
			expectThreat:  ThreatNone,
		},
		{
			name:          "Clean query with normal words",
			method:        http.MethodGet,
			path:          "/api/search",
			query:         "q=select+shoes+for+running",
			expectBlocked: false,
			expectThreat:  ThreatNone,
		},

		// SQL Injection Tests
		{
			name:          "SQLi: Classic OR 1=1 in query",
			method:        http.MethodGet,
			path:          "/api/users",
			query:         "id=1%27+OR+1%3D1+--",
			expectBlocked: true,
			expectThreat:  ThreatSQLi,
		},
		{
			name:          "SQLi: UNION SELECT in JSON body",
			method:        http.MethodPost,
			path:          "/api/query",
			body:          []byte(`{"query":"admin' UNION SELECT null, username, password FROM users --"}`),
			expectBlocked: true,
			expectThreat:  ThreatSQLi,
		},
		{
			name:          "SQLi: Stacked queries with DROP TABLE",
			method:        http.MethodPost,
			path:          "/api/save",
			body:          []byte(`{"id":"10; DROP TABLE users;"}`),
			expectBlocked: true,
			expectThreat:  ThreatSQLi,
		},

		// XSS Tests
		{
			name:          "XSS: Script tag in query string",
			method:        http.MethodGet,
			path:          "/api/profile",
			query:         "name=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
			expectBlocked: true,
			expectThreat:  ThreatXSS,
		},
		{
			name:          "XSS: IMG onerror in JSON body",
			method:        http.MethodPost,
			path:          "/api/comments",
			body:          []byte(`{"comment":"<img src=x onerror=alert('xss')>"}`),
			expectBlocked: true,
			expectThreat:  ThreatXSS,
		},
		{
			name:          "XSS: Javascript URI in header",
			method:        http.MethodGet,
			path:          "/api/dashboard",
			headers:       http.Header{"Referer": []string{"javascript:eval('malicious')"}},
			expectBlocked: true,
			expectThreat:  ThreatXSS,
		},

		// Command Injection Tests
		{
			name:          "CMD: Semicolon cat /etc/passwd in query",
			method:        http.MethodGet,
			path:          "/api/ping",
			query:         "host=127.0.0.1;cat+/etc/passwd",
			expectBlocked: true,
			expectThreat:  ThreatCMDInjection,
		},
		{
			name:          "CMD: Subshell $(whoami) in JSON body",
			method:        http.MethodPost,
			path:          "/api/exec",
			body:          []byte(`{"target":"127.0.0.1 $(whoami)"}`),
			expectBlocked: true,
			expectThreat:  ThreatCMDInjection,
		},
		{
			name:          "CMD: Pipe to sh",
			method:        http.MethodPost,
			path:          "/api/tools",
			body:          []byte(`{"cmd":"echo test | /bin/sh"}`),
			expectBlocked: true,
			expectThreat:  ThreatCMDInjection,
		},

		// Path Traversal Tests
		{
			name:          "Path Traversal: ../../etc/passwd in path",
			method:        http.MethodGet,
			path:          "/api/download/../../../../etc/passwd",
			expectBlocked: true,
			expectThreat:  ThreatPathTraversal,
		},
		{
			name:          "Path Traversal: URL encoded ..%2f in query",
			method:        http.MethodGet,
			path:          "/api/files",
			query:         "file=..%2f..%2f..%2fwindows%2fsystem32",
			expectBlocked: true,
			expectThreat:  ThreatPathTraversal,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := tc.headers
			if headers == nil {
				headers = http.Header{}
			}
			result := engine.Inspect(tc.method, tc.path, tc.query, headers, tc.body)
			if result.Blocked != tc.expectBlocked {
				t.Errorf("expected Blocked=%v, got Blocked=%v (Reason: %s, Rule: %s, Sample: %s)",
					tc.expectBlocked, result.Blocked, result.Reason, result.MatchedRule, result.MatchedSample)
			}
			if tc.expectBlocked && result.ThreatType != tc.expectThreat {
				t.Errorf("expected ThreatType=%s, got %s", tc.expectThreat, result.ThreatType)
			}
		})
	}
}

func BenchmarkFastPathWAF(b *testing.B) {
	engine := NewEngine(DefaultConfig())
	body := []byte(`{"messages":[{"role":"user","content":"Tell me a story about a dragon and a programmer"}]}`)
	headers := http.Header{"User-Agent": []string{"Mozilla/5.0"}, "Accept": []string{"application/json"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Inspect(http.MethodPost, "/v1/chat/completions", "model=gpt-4", headers, body)
	}
}
