package router

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"noject/internal/audit"
	"noject/internal/auth"
	"noject/internal/guardclient"
	"noject/internal/metrics"
	"noject/internal/waf"
)

// GatewayHandler orchestrates authentication, fast-path WAF, AI guardrails, reverse proxying, and ISO audit logging.
type GatewayHandler struct {
	table        *Table
	auth         auth.Authenticator
	wafEngine    *waf.Engine
	guardClient  *guardclient.Client
	auditLogger  audit.Logger
	httpClient   *http.Client
	maxBodyBytes int64
	// trustedProxies are the peers whose X-Forwarded-For header may be
	// believed. Empty means "no proxy in front" — the header is ignored.
	trustedProxies []*net.IPNet
}

// DefaultMaxBodyBytes bounds request bodies the gateway will buffer when
// no explicit limit is configured.
const DefaultMaxBodyBytes int64 = 10 << 20 // 10 MiB

// HandlerConfig holds configuration for the GatewayHandler.
type HandlerConfig struct {
	Table       *Table
	Auth        auth.Authenticator
	WAFEngine   *waf.Engine
	GuardClient *guardclient.Client
	AuditLogger audit.Logger
	// MaxBodyBytes caps how much request body is read into memory.
	// Defaults to DefaultMaxBodyBytes when zero or negative.
	MaxBodyBytes int64
	// TrustedProxies lists CIDRs whose X-Forwarded-For header is believed.
	// Leave empty unless the gateway really is behind a proxy: an empty
	// list is the safe default, since it makes RemoteAddr authoritative.
	TrustedProxies []string
}

// NewGatewayHandler creates a fully initialized GatewayHandler.
func NewGatewayHandler(cfg HandlerConfig) *GatewayHandler {
	if cfg.WAFEngine == nil {
		cfg.WAFEngine = waf.NewEngine(waf.DefaultConfig())
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
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
		maxBodyBytes:   cfg.MaxBodyBytes,
		trustedProxies: parseCIDRs(cfg.TrustedProxies),
	}
}

// parseCIDRs converts configured trusted-proxy entries to networks. A bare
// IP is accepted and treated as a single-host network. Unparseable entries
// are skipped rather than silently widening trust.
func parseCIDRs(entries []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, network)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
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

// clientIP resolves the address recorded in the audit trail.
//
// X-Forwarded-For is set by the client and is trivially forged: a request
// carrying "X-Forwarded-For: 1.2.3.4" previously caused every audit record
// for that attack to name 1.2.3.4 instead of the real peer. An audit trail
// the attacker can write to is worse than none — it launders their identity
// and can frame an innocent address, while the hash chain attests to the
// forged value as faithfully as it would a true one.
//
// The header is therefore honoured ONLY when the immediate peer is a
// configured trusted proxy. With no proxy configured, it is ignored
// entirely and RemoteAddr is authoritative.
func (h *GatewayHandler) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if len(h.trustedProxies) == 0 {
		return remote
	}

	host := remote
	if parsed, _, err := net.SplitHostPort(remote); err == nil {
		host = parsed
	}
	peer := net.ParseIP(host)
	if peer == nil || !h.isTrustedProxy(peer) {
		return remote
	}

	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return remote
	}
	// Walk right-to-left and take the first address that is NOT itself a
	// trusted proxy: that is the earliest hop we can still vouch for. The
	// leftmost entry is whatever the client prepended — the forgeable part.
	parts := strings.Split(forwarded, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.TrimSpace(parts[i]))
		if candidate == nil {
			continue
		}
		if !h.isTrustedProxy(candidate) {
			return candidate.String()
		}
	}
	return remote
}

func (h *GatewayHandler) isTrustedProxy(ip net.IP) bool {
	for _, cidr := range h.trustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
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
		// Every message is inspected, not just the last: an injection or
		// PII planted in the system prompt or an earlier turn reaches the
		// upstream model just as effectively. Contents are joined with
		// promptSeparator so replacePromptInBody can map the sanitized
		// text back to the individual messages it came from.
		if msgs, ok := jsonMap["messages"].([]interface{}); ok {
			var contents []string
			for _, m := range msgs {
				if msgMap, ok := m.(map[string]interface{}); ok {
					if content, ok := msgMap["content"].(string); ok {
						contents = append(contents, content)
					}
				}
			}
			if len(contents) > 0 {
				return strings.Join(contents, promptSeparator)
			}
		}

		// 2. Simple prompt format: {"prompt":"..."} or {"query":"..."} or {"input":"..."}.
		// Collect every recognized key, not just the first: returning only the
		// first match lets a body smuggle a second, unscanned payload under a
		// different key ({"prompt":"hello","input":"ignore all previous ..."}).
		// Joining them with promptSeparator keeps the guard's view aligned with
		// what the upstream model will actually receive.
		var flatParts []string
		for _, key := range []string{"prompt", "query", "input", "text", "message"} {
			if strVal, ok := jsonMap[key].(string); ok && strVal != "" {
				flatParts = append(flatParts, strVal)
			}
		}
		if len(flatParts) > 0 {
			return strings.Join(flatParts, promptSeparator)
		}
	}

	return string(body)
}

// promptSeparator joins message contents when flattening a conversation for
// inspection, and splits the guard's sanitized text back into per-message
// parts. It must be a sequence that will not occur inside message content
// and that the guard's PII masking will not rewrite.
const promptSeparator = "\n␞\n" // U+241E SYMBOL FOR RECORD SEPARATOR

// replacePromptInBody writes the guard's sanitized text back into the JSON
// body, restoring it to EVERY message it was extracted from.
//
// Previously this assigned the sanitized text to only the last message.
// Because extractPrompt flattens the whole conversation into one string,
// that had two consequences: every earlier message (including the system
// prompt and prior turns) was forwarded upstream with its original,
// unmasked content — so PII the guard had detected still left the gateway —
// and the last message was overwritten with the entire flattened
// conversation, destroying the turn structure the upstream model relies on.
func replacePromptInBody(originalBody []byte, sanitizedPrompt string) []byte {
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(originalBody, &jsonMap); err == nil {
		if msgs, ok := jsonMap["messages"].([]interface{}); ok && len(msgs) > 0 {
			// Collect the messages that carry string content, in the same
			// order extractPrompt walked them.
			var contentMsgs []map[string]interface{}
			for _, m := range msgs {
				if msgMap, ok := m.(map[string]interface{}); ok {
					if _, ok := msgMap["content"].(string); ok {
						contentMsgs = append(contentMsgs, msgMap)
					}
				}
			}

			if len(contentMsgs) > 0 {
				parts := strings.Split(sanitizedPrompt, promptSeparator)
				if len(parts) == len(contentMsgs) {
					// Normal path: sanitization preserved the separators, so
					// each part maps back to its originating message.
					for i, msgMap := range contentMsgs {
						msgMap["content"] = parts[i]
					}
				} else {
					// The guard collapsed or altered the separators (e.g. a
					// rewrite spanning a boundary). Falling back to writing
					// the whole blob into one message would silently forward
					// the other messages unsanitized, so instead put the full
					// sanitized text in the last message and blank the rest:
					// content is lost, but nothing unsanitized escapes.
					last := len(contentMsgs) - 1
					for i, msgMap := range contentMsgs {
						if i == last {
							msgMap["content"] = sanitizedPrompt
						} else {
							msgMap["content"] = ""
						}
					}
				}
				if newBody, err := json.Marshal(jsonMap); err == nil {
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

	clientIP := h.clientIP(r)

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

	// Reject protocol-upgrade requests on routes that are not explicitly
	// WebSocket-capable. An Upgrade accepted here would pivot the connection
	// to a bidirectional stream that escapes per-request body inspection —
	// round-5 red-team confirmed the gateway passed Upgrade through.
	if upg := r.Header.Get("Upgrade"); upg != "" && !strings.EqualFold(route.Type, "ws") && !strings.EqualFold(route.Type, "websocket") {
		h.writeError(w, http.StatusBadRequest, traceID, "PROTOCOL_UPGRADE_REJECTED", "NONE", "Upgrade requests are not permitted on this route", 0)
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

	// Read Request Body, bounded. The whole body is buffered in memory for
	// WAF and guard inspection, so an unbounded read lets a few large
	// concurrent uploads exhaust the gateway's memory. Over-limit requests
	// are rejected with 413 rather than truncated — a truncated body would
	// be inspected clean and then forwarded incomplete.
	var body []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, h.maxBodyBytes+1)
		body, _ = io.ReadAll(limited)
		if int64(len(body)) > h.maxBodyBytes {
			h.writeError(w, http.StatusRequestEntityTooLarge, traceID,
				"payload_too_large", "NONE",
				"request body exceeds maximum allowed size", 0)
			return
		}
	}

	body, bodyWasDecoded, err := decodeContentEncodedBody(body, r.Header.Get("Content-Encoding"), h.maxBodyBytes)
	if err != nil {
		switch {
		case errors.Is(err, errDecodedBodyTooLarge):
			h.writeError(w, http.StatusRequestEntityTooLarge, traceID,
				"payload_too_large", "NONE", err.Error(), 0)
		case errors.Is(err, errUnsupportedEncoding):
			h.writeError(w, http.StatusUnsupportedMediaType, traceID,
				"unsupported_content_encoding", "NONE", err.Error(), 0)
		default:
			h.writeError(w, http.StatusBadRequest, traceID,
				"invalid_content_encoding", "NONE", err.Error(), 0)
		}
		return
	}

	var wafDuration, guardDuration, proxyDuration time.Duration

	// 3. Fast-Path WAF Check
	if route.Guardrails.FastWAF {
		wafStart := time.Now()
		wafRes := h.wafEngine.Inspect(r.Method, r.URL.Path, r.URL.RawQuery, r.Header, body)
		wafDuration = time.Since(wafStart)

		if wafRes.Blocked {
			ev := audit.Event{
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
			}
			_ = h.auditLogger.LogEvent(ev)
			metrics.Default().RecordRequest(http.StatusForbidden, "BLOCKED", string(wafRes.ThreatType), wafDuration, 0, 0, &metrics.SecurityEvent{
				Timestamp:      time.Now().UTC(),
				TraceID:        traceID,
				ClientID:       clientID,
				ClientIP:       clientIP,
				Route:          route.Path,
				Action:         "BLOCKED",
				ThreatCategory: string(wafRes.ThreatType),
				Severity:       string(wafRes.Severity),
				Confidence:     1.0,
				Reason:         wafRes.Reason,
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

	if (route.Guardrails.PromptInjection || route.Guardrails.Jailbreak || route.Guardrails.PIIMasking || route.Guardrails.AgenticSentinel) && h.guardClient != nil {
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
					EnableAgenticSentinel: route.Guardrails.AgenticSentinel,
					SensitivityThreshold:  0.7,
				},
			}

			guardStart := time.Now()
			guardRes, err := h.guardClient.InspectRequest(r.Context(), guardReq)
			guardDuration = time.Since(guardStart)

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
				metrics.Default().RecordRequest(http.StatusForbidden, "BLOCKED", guardRes.ThreatType, wafDuration, guardDuration, 0, &metrics.SecurityEvent{
					Timestamp:      time.Now().UTC(),
					TraceID:        traceID,
					ClientID:       clientID,
					ClientIP:       clientIP,
					Route:          route.Path,
					Action:         "BLOCKED",
					ThreatCategory: guardRes.ThreatType,
					Severity:       guardRes.RiskLevel,
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

	// Copy and pass through headers. Hop-by-hop headers must not ride to the
	// upstream: Connection declares per-hop dropping, Trailer attaches data
	// the body inspector never saw, Transfer-Encoding/Content-Length disagree
	// and enable CL.TE desync, Upgrade rides persistent tunnels past
	// per-request inspection. Strip them all and let Go's http.Client
	// re-derive framing from the inspected body.
	hopByHop := map[string]bool{
		"connection": true, "proxy-connection": true, "keep-alive": true,
		"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
	}
	// Connection may also name additional headers to drop per-hop
	if connHdr := r.Header.Get("Connection"); connHdr != "" {
		for _, token := range strings.Split(connHdr, ",") {
			if t := strings.TrimSpace(token); t != "" {
				hopByHop[strings.ToLower(t)] = true
			}
		}
	}
	for k, vv := range r.Header {
		kl := strings.ToLower(k)
		if hopByHop[kl] {
			continue
		}
		if bodyWasDecoded && (strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Content-Length")) {
			continue
		}
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}
	// Recompute framing from the inspected body so Content-Length and the
	// wire encoding agree — this is the actual CL.TE smuggling fix.
	proxyReq.ContentLength = int64(len(forwardBody))
	proxyReq.Header.Set("X-Trace-ID", traceID)
	proxyReq.Header.Set("X-Forwarded-For", clientIP)

	proxyStart := time.Now()
	resp, err := h.httpClient.Do(proxyReq)
	proxyDuration = time.Since(proxyStart)

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

	// Bound the upstream response read. A compromised upstream returning an
	// unbounded body would otherwise be buffered whole into gateway memory —
	// memory DoS via upstream trust is its own attack class.
	maxResp := h.maxBodyBytes
	if maxResp <= 0 {
		maxResp = DefaultMaxBodyBytes
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResp+1))
	if int64(len(respBody)) > maxResp {
		h.writeError(w, http.StatusBadGateway, traceID, "UPSTREAM_TOO_LARGE", "NONE", "upstream response exceeds maximum allowed size", 0)
		return
	}

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
			metrics.Default().RecordRequest(http.StatusBadGateway, "BLOCKED", "CANARY_LEAK", wafDuration, guardDuration, proxyDuration, &metrics.SecurityEvent{
				Timestamp:      time.Now().UTC(),
				TraceID:        traceID,
				ClientID:       clientID,
				ClientIP:       clientIP,
				Route:          route.Path,
				Action:         "BLOCKED",
				ThreatCategory: "CANARY_LEAK",
				Severity:       "CRITICAL",
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

	var eventRecord *metrics.SecurityEvent
	if action == audit.ActionMasked {
		eventRecord = &metrics.SecurityEvent{
			Timestamp:      time.Now().UTC(),
			TraceID:        traceID,
			ClientID:       clientID,
			ClientIP:       clientIP,
			Route:          route.Path,
			Action:         "MASKED",
			ThreatCategory: "PII_DETECTED",
			Severity:       "MEDIUM",
			Confidence:     guardConfidence,
			Reason:         guardReason,
		}
	}
	metrics.Default().RecordRequest(resp.StatusCode, string(action), string(threatCategory), wafDuration, guardDuration, proxyDuration, eventRecord)

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
