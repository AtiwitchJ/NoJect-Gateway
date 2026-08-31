package waf

import (
	"net/http"
	"testing"
)

func BenchmarkVector_SQLi(b *testing.B) {
	payload := "id=1' UNION SELECT null, username, password FROM users --"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checkSQLi(payload)
	}
}

func BenchmarkVector_XSS(b *testing.B) {
	payload := "<script>alert('xss_attack_vector')</script>"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checkXSS(payload)
	}
}

func BenchmarkVector_CommandInjection(b *testing.B) {
	payload := "127.0.0.1; cat /etc/passwd | /bin/sh"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checkCommandInjection(payload)
	}
}

func BenchmarkVector_PathTraversal(b *testing.B) {
	payload := "../../etc/shadow"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checkPathTraversal(payload)
	}
}

func BenchmarkVector_Full_WAF_Clean(b *testing.B) {
	engine := NewEngine(DefaultConfig())
	headers := http.Header{"User-Agent": []string{"Mozilla/5.0"}, "Accept": []string{"application/json"}}
	body := []byte(`{"messages":[{"role":"user","content":"Can you explain the difference between microservices and monolith?"}]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Inspect(http.MethodPost, "/api/v1/query", "category=tech&page=1", headers, body)
	}
}

func BenchmarkVector_Full_WAF_Attack(b *testing.B) {
	engine := NewEngine(DefaultConfig())
	headers := http.Header{"User-Agent": []string{"Mozilla/5.0"}}
	body := []byte(`{"query":"admin' UNION SELECT null, password FROM users --"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Inspect(http.MethodPost, "/api/v1/query", "search=test;cat /etc/passwd", headers, body)
	}
}
