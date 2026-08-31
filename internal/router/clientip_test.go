package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// X-Forwarded-For is client-controlled. Believing it unconditionally lets an
// attacker choose the IP recorded against their own attacks in the audit
// trail — laundering their identity and potentially framing a third party,
// with the hash chain attesting to the forged value.
func TestClientIP_ForgedXFFIgnoredWithoutTrustedProxy(t *testing.T) {
	h := NewGatewayHandler(HandlerConfig{Table: NewTable(nil)})

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.RemoteAddr = "198.51.100.9:44321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := h.clientIP(req)
	if got != "198.51.100.9:44321" {
		t.Fatalf("forged X-Forwarded-For was believed: got %q, want the real peer", got)
	}
}

func TestClientIP_HonouredBehindTrustedProxy(t *testing.T) {
	h := NewGatewayHandler(HandlerConfig{
		Table:          NewTable(nil),
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.RemoteAddr = "10.0.0.5:44321"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	if got := h.clientIP(req); got != "203.0.113.7" {
		t.Fatalf("trusted proxy XFF not honoured: got %q", got)
	}
}

// A client behind a trusted proxy can still prepend entries to the header.
// Taking the leftmost value would return whatever they injected, so the
// rightmost non-proxy hop is the earliest address we can actually vouch for.
func TestClientIP_PrependedEntriesIgnored(t *testing.T) {
	h := NewGatewayHandler(HandlerConfig{
		Table:          NewTable(nil),
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.RemoteAddr = "10.0.0.5:44321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.7")

	if got := h.clientIP(req); got != "203.0.113.7" {
		t.Fatalf("client-prepended XFF entry was believed: got %q", got)
	}
}

func TestClientIP_UntrustedPeerCannotForge(t *testing.T) {
	h := NewGatewayHandler(HandlerConfig{
		Table:          NewTable(nil),
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.RemoteAddr = "198.51.100.9:44321" // not in the trusted range
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := h.clientIP(req); got != "198.51.100.9:44321" {
		t.Fatalf("untrusted peer forged its IP: got %q", got)
	}
}

// extractPrompt only collected string content, so a message whose content was
// a JSON number passed through the guard entirely uninspected.
func TestExtractPrompt_NonStringContentIsNotSilentlySkipped(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":12345}]}`)
	if got := extractPrompt(body); got == "" {
		t.Fatal("numeric message content yielded an empty prompt: it would reach the upstream model uninspected")
	}
}
