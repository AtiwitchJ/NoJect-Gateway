package router

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"noject/internal/audit"
	"noject/internal/auth"
	"noject/internal/guardclient"
	"noject/internal/waf"
)

// GatewayHandler orchestrates authentication, fast-path WAF, AI guardrails, reverse proxying, and ISO audit logging.
type GatewayHandler struct {
	table       *Table
	auth        auth.Authenticator
	wafEngine   *waf.Engine
	guardClient *guardclient.Client
	auditLogger audit.Logger
	httpClient  *http.Client
}

// HandlerConfig holds configuration for the GatewayHandler.
type HandlerConfig struct {
	Table       *Table
	Auth        auth.Authenticator
	WAFEngine   *waf.Engine
	GuardClient *guardclient.Client
	AuditLogger audit.Logger
}

// NewGatewayHandler creates a fully initialized GatewayHandler.
func NewGatewayHandler(cfg HandlerConfig) *GatewayHandler {
	if cfg.WAFEngine == nil {
		cfg.WAFEngine = waf.NewEngine(waf.DefaultConfig())
	}
	return &GatewayHandler{
		table:       cfg.Table,
		auth:        cfg.Auth,
		wafEngine:   cfg.WAFEngine,
		guardClient: cfg.GuardClient,
		auditLogger: cfg.AuditLogger,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// generateTraceID creates a W3C traceparent compatible identifier.
func generateTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	p := make([]byte, 8)
	_, _ = rand.Read(p)
	return fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(b), hex.EncodeToString(p))
}

// ErrorResponse represents standard structured error output.
type ErrorResponse struct {
	Error      string  `json:"error"`
	ThreatType string  `json:"threat_type,omitempty"`
	Reason     string  `json:"reason"`
	TraceID    string  `json:"trace_id"`
	Confidence float64 `json:"confidence,omitempty"`
}

func (h *GatewayHandler) writeError(w http.ResponseWriter, status int, traceID, errType, threatType, reason string, confidence float64) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Trace-ID", traceID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error:      errType,
		ThreatType: threatType,
		Reason:     reason,
		TraceID:    traceID,
		Confidence: confidence,
	})
}

// extractPrompt attempts to extract natural language prompt from LLM requests or generic bodies.
func extractPrompt(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(body, &jsonMap); err == nil {
		// 1. OpenAI format: {"messages":[{"role":"user","content":"..."}]}
		if msgs, ok := jsonMap["messages"].([]interface{}); ok {
			var builder strings.Builder
			for _, m := range msgs {
				if msgMap, ok := m.(map[string]interface{}); ok {
					if content, ok := msgMap["content"].(string); ok {
						builder.WriteString(content)
						builder.WriteString(" ")
					}
				}
			}
			if builder.Len() > 0 {
				return strings.TrimSpace(builder.String())
			}
		}

		// 2. Simple prompt format: {"prompt":"..."} or {"query":"..."} or {"input":"..."}
		for _, key := range []string{"prompt", "query", "input", "text", "message"} {
			if strVal, ok := jsonMap[key].(string); ok {
				return strVal
			}
		}
	}

	return string(body)
}

// replacePromptInBody updates the JSON body with the sanitized prompt text.
func replacePromptInBody(originalBody []byte, sanitizedPrompt string) []byte {
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(originalBody, &jsonMap); err == nil {
		// Replace in OpenAI messages if last message is user
		if msgs, ok := jsonMap["messages"].([]interface{}); ok && len(msgs) > 0 {
			if lastMsg, ok := msgs[len(msgs)-1].(map[string]interface{}); ok {
				lastMsg["content"] = sanitizedPrompt
				newBody, err := json.Marshal(jsonMap)
				if err == nil {
					return newBody
				}
			}
		}
		// Replace in top-level fields
		for _, key := range []string{"prompt", "query", "input", "text", "message"} {
			if _, ok := jsonMap[key]; ok {
				jsonMap[key] = sanitizedPrompt
				newBody, err := json.Marshal(jsonMap)
				if err == nil {
					return newBody
				}
			}
		}
	}
	return []byte(sanitizedPrompt)
}

func (h *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceID := r.Header.Get("X-Trace-ID")
	if traceID == "" {
		traceID = generateTraceID()
	}

	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = strings.Split(forwarded, ",")[0]
	}

	// 1. Route Matching
	targetPath := r.URL.Path
	if r.URL.RawPath != "" {
		targetPath = r.URL.RawPath
	}

	// Also check raw RequestURI / query for path traversal early
	if strings.Contains(r.RequestURI, "..") || strings.Contains(r.URL.RawQuery, "..") {
		wafRes := h.wafEngine.Inspect(r.Method, r.RequestURI, r.URL.RawQuery, r.Header, nil)
		if wafRes.Blocked {
			_ = h.auditLogger.LogEvent(audit.Event{
				TraceID:        traceID,
				ClientID:       "anonymous",
				ClientIP:       clientIP,
				Route:          targetPath,
				Action:         audit.ActionBlocked,
				ThreatCategory: audit.ThreatCategory(wafRes.ThreatType),
				Severity:       audit.Severity(wafRes.Severity),
				Confidence:     1.0,
				Reason:         wafRes.Reason,
				MatchedRule:    wafRes.MatchedRule,
			})
			h.writeError(w, http.StatusForbidden, traceID, "SECURITY_VIOLATION", string(wafRes.ThreatType), wafRes.Reason, 1.0)
			return
		}
	}

	route, matched := h.table.Match(targetPath)
	if !matched {
		h.writeError(w, http.StatusNotFound, traceID, "ROUTE_NOT_FOUND", "NONE", "no matching route found for path", 0)
		return
	}

	// 2. Authentication Check
	var authCtx *auth.AuthContext
	var err error
	if route.AuthRequired {
		if h.auth == nil {
			h.writeError(w, http.StatusInternalServerError, traceID, "AUTH_CONFIGURATION_ERROR", "NONE", "authenticator not configured", 0)
			return
		}
		authCtx, err = h.auth.Authenticate(r)
		if err != nil {
			_ = h.auditLogger.LogEvent(audit.Event{
				TraceID:        traceID,
				ClientIP:       clientIP,
				Route:          route.Path,
				Action:         audit.ActionBlocked,
				ThreatCategory: audit.ThreatCategoryNone,
				Severity:       audit.SeverityHigh,
				Reason:         fmt.Sprintf("Authentication failed: %v", err),
			})
			h.writeError(w, http.StatusUnauthorized, traceID, "UNAUTHORIZED", "NONE", err.Error(), 0)
			return
		}

		// Check Required Roles
		for _, requiredRole := range route.RequiredRoles {
			if !authCtx.HasRole(requiredRole) {
				_ = h.auditLogger.LogEvent(audit.Event{
					TraceID:        traceID,
					ClientID:       authCtx.Subject,
					ClientIP:       clientIP,
					Route:          route.Path,
					Action:         audit.ActionBlocked,
					ThreatCategory: audit.ThreatCategoryNone,
					Severity:       audit.SeverityHigh,
					Reason:         fmt.Sprintf("Insufficient permissions: missing role '%s'", requiredRole),
				})
				h.writeError(w, http.StatusForbidden, traceID, "FORBIDDEN", "NONE", "insufficient role permissions", 0)
				return
			}
		}
	}

	clientID := "anonymous"
	if authCtx != nil {
		clientID = authCtx.Subject
	}

	// Read Request Body
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}

	// 3. Fast-Path WAF Check
	if route.Guardrails.FastWAF {
		wafRes := h.wafEngine.Inspect(r.Method, r.URL.Path, r.URL.RawQuery, r.Header, body)
		if wafRes.Blocked {
			_ = h.auditLogger.LogEvent(audit.Event{
				TraceID:        traceID,
				ClientID:       clientID,
				ClientIP:       clientIP,
				Route:          route.Path,
				Action:         audit.ActionBlocked,
				ThreatCategory: audit.ThreatCategory(wafRes.ThreatType),
				Severity:       audit.Severity(wafRes.Severity),
				Confidence:     1.0,
				Reason:         wafRes.Reason,
				MatchedRule:    wafRes.MatchedRule,
			})
			h.writeError(w, http.StatusForbidden, traceID, "SECURITY_VIOLATION", string(wafRes.ThreatType), wafRes.Reason, 1.0)
			return
		}
	}

	// 4. AI Guardrail Inspection (Prompt Injection, Jailbreak, PII Masking)
	forwardBody := body
	action := audit.ActionAllowed
	threatCategory := audit.ThreatCategoryNone
	var guardReason string
	var guardConfidence float64

	if (route.Guardrails.PromptInjection || route.Guardrails.Jailbreak || route.Guardrails.PIIMasking) && h.guardClient != nil {
		promptText := extractPrompt(body)
		if promptText != "" {
			guardReq := guardclient.InspectRequestPayload{
				TraceID: traceID,
				Route:   route.Path,
				Prompt:  promptText,
				Policies: guardclient.Policies{
					EnablePromptInjection: route.Guardrails.PromptInjection,
					EnableJailbreak:       route.Guardrails.Jailbreak,
					EnablePIIMasking:      route.Guardrails.PIIMasking,
					SensitivityThreshold:  0.7,
				},
			}

			guardRes, err := h.guardClient.InspectRequest(r.Context(), guardReq)
			if err != nil {
				_ = h.auditLogger.LogEvent(audit.Event{
					TraceID:        traceID,
					ClientID:       clientID,
					ClientIP:       clientIP,
					Route:          route.Path,
					Action:         audit.ActionBlocked,
					ThreatCategory: audit.ThreatCategoryNone,
					Severity:       audit.SeverityHigh,
					Reason:         fmt.Sprintf("AI Guard Engine error: %v", err),
				})
				h.writeError(w, http.StatusBadGateway, traceID, "GUARD_ENGINE_ERROR", "NONE", err.Error(), 0)
				return
			}

			if !guardRes.Allowed {
				_ = h.auditLogger.LogEvent(audit.Event{
					TraceID:        traceID,
					ClientID:       clientID,
					ClientIP:       clientIP,
					Route:          route.Path,
					Action:         audit.ActionBlocked,
					ThreatCategory: audit.ThreatCategory(guardRes.ThreatType),
					Severity:       audit.Severity(guardRes.RiskLevel),
					Confidence:     guardRes.Confidence,
					Reason:         guardRes.Reason,
				})
				h.writeError(w, http.StatusForbidden, traceID, "AI_SECURITY_VIOLATION", guardRes.ThreatType, guardRes.Reason, guardRes.Confidence)
				return
			}

			// Apply PII Masking if text was sanitized
			if guardRes.SanitizedPrompt != promptText {
				action = audit.ActionMasked
				threatCategory = audit.ThreatCategoryPII
				guardReason = guardRes.Reason
				guardConfidence = guardRes.Confidence
				forwardBody = replacePromptInBody(body, guardRes.SanitizedPrompt)
			}
		}
	}

	// 5. Upstream Reverse Proxy Forwarding
	upstreamURL, err := url.Parse(route.Upstream)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, traceID, "INVALID_UPSTREAM_URL", "NONE", err.Error(), 0)
		return
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bytes.NewReader(forwardBody))
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, traceID, "PROXY_REQUEST_CREATION_FAILED", "NONE", err.Error(), 0)
		return
	}

	// Copy and pass through headers
	for k, vv := range r.Header {
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}
	proxyReq.Header.Set("X-Trace-ID", traceID)
	proxyReq.Header.Set("X-Forwarded-For", clientIP)

	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		_ = h.auditLogger.LogEvent(audit.Event{
			TraceID:        traceID,
			ClientID:       clientID,
			ClientIP:       clientIP,
			Route:          route.Path,
			Action:         audit.ActionBlocked,
			ThreatCategory: audit.ThreatCategoryNone,
			Severity:       audit.SeverityHigh,
			Reason:         fmt.Sprintf("Upstream connection failure: %v", err),
		})
		h.writeError(w, http.StatusBadGateway, traceID, "UPSTREAM_UNAVAILABLE", "NONE", fmt.Sprintf("failed to reach upstream: %v", err), 0)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// 6. Response Guardrail Check (Canary Tokens)
	if route.Guardrails.OutputGuard && len(route.CanaryTokens) > 0 && h.guardClient != nil {
		outReq := guardclient.InspectOutputPayload{
			TraceID:      traceID,
			ResponseText: string(respBody),
			CanaryTokens: route.CanaryTokens,
		}
		outRes, err := h.guardClient.InspectResponse(r.Context(), outReq)
		if err == nil && !outRes.Allowed {
			_ = h.auditLogger.LogEvent(audit.Event{
				TraceID:        traceID,
				ClientID:       clientID,
				ClientIP:       clientIP,
				Route:          route.Path,
				Action:         audit.ActionBlocked,
				ThreatCategory: audit.ThreatCategoryCanaryLeak,
				Severity:       audit.SeverityCritical,
				Confidence:     1.0,
				Reason:         outRes.Reason,
			})
			h.writeError(w, http.StatusBadGateway, traceID, "CANARY_SECRET_LEAK", "CANARY_LEAK", "upstream response blocked due to sensitive canary token leakage", 1.0)
			return
		}
	}

	// 7. Log ISO Audit Event
	_ = h.auditLogger.LogEvent(audit.Event{
		TraceID:        traceID,
		ClientID:       clientID,
		ClientIP:       clientIP,
		Route:          route.Path,
		Action:         action,
		ThreatCategory: threatCategory,
		Severity:       audit.SeverityLow,
		Confidence:     guardConfidence,
		Reason:         guardReason,
	})

	// 8. Write Response to Client
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Trace-ID", traceID)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}
