package router

import (
	"path"
	"strings"
)

// RouteGuardrails enables or disables specific security and AI guardrail checks per route.
type RouteGuardrails struct {
	FastWAF          bool `json:"fast_waf" yaml:"fast_waf"`
	PromptInjection  bool `json:"prompt_injection" yaml:"prompt_injection"`
	Jailbreak        bool `json:"jailbreak" yaml:"jailbreak"`
	PIIMasking       bool `json:"pii_masking" yaml:"pii_masking"`
	OutputGuard      bool `json:"output_guard" yaml:"output_guard"`
}

// Route defines an upstream routing destination and its security policies.
type Route struct {
	ID            string          `json:"id" yaml:"id"`
	Path          string          `json:"path" yaml:"path"`
	Upstream      string          `json:"upstream" yaml:"upstream"`
	Type          string          `json:"type" yaml:"type"` // "llm" or "rest"
	AuthRequired  bool            `json:"auth_required" yaml:"auth_required"`
	RequiredRoles []string        `json:"required_roles,omitempty" yaml:"required_roles,omitempty"`
	CanaryTokens  []string        `json:"canary_tokens,omitempty" yaml:"canary_tokens,omitempty"`
	Guardrails    RouteGuardrails `json:"guardrails" yaml:"guardrails"`
}

// Table manages configured routes and performs fast route matching.
type Table struct {
	routes []Route
}

// NewTable creates a new Route Table.
func NewTable(routes []Route) *Table {
	return &Table{routes: routes}
}

// Match finds the best matching Route for an incoming request path.
func (t *Table) Match(reqPath string) (*Route, bool) {
	reqPath = path.Clean(reqPath)

	// 1. Exact match pass
	for _, r := range t.routes {
		cleaned := path.Clean(r.Path)
		if cleaned == reqPath {
			routeCopy := r
			return &routeCopy, true
		}
	}

	// 2. Wildcard / Prefix match pass
	for _, r := range t.routes {
		cleaned := path.Clean(r.Path)
		if strings.HasSuffix(cleaned, "/*") {
			prefix := strings.TrimSuffix(cleaned, "/*")
			if strings.HasPrefix(reqPath, prefix) {
				routeCopy := r
				return &routeCopy, true
			}
		} else if strings.HasSuffix(cleaned, "*") {
			prefix := strings.TrimSuffix(cleaned, "*")
			if strings.HasPrefix(reqPath, prefix) {
				routeCopy := r
				return &routeCopy, true
			}
		}
	}

	return nil, false
}
