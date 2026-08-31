package guardclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGuardClient(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/inspect/request" {
			var req InspectRequestPayload
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Prompt == "malicious prompt" {
				_ = json.NewEncoder(w).Encode(InspectRequestResponse{
					Allowed:    false,
					ThreatType: "PROMPT_INJECTION",
					RiskLevel:  "CRITICAL",
					Confidence: 0.99,
					Reason:     "Attack detected",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(InspectRequestResponse{
				Allowed:         true,
				SanitizedPrompt: req.Prompt,
				ThreatType:      "NONE",
			})
		}
	}))
	defer mockServer.Close()

	client := NewClient(Config{
		Endpoint: mockServer.URL,
		Timeout:  2 * time.Second,
	})

	t.Run("Safe Request Inspection", func(t *testing.T) {
		resp, err := client.InspectRequest(context.Background(), InspectRequestPayload{
			TraceID: "00-test-123-01",
			Prompt:  "Clean prompt",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Allowed {
			t.Error("expected allowed=true for clean prompt")
		}
	})

	t.Run("Malicious Request Inspection", func(t *testing.T) {
		resp, err := client.InspectRequest(context.Background(), InspectRequestPayload{
			TraceID: "00-test-123-01",
			Prompt:  "malicious prompt",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Allowed {
			t.Error("expected allowed=false for malicious prompt")
		}
		if resp.ThreatType != "PROMPT_INJECTION" {
			t.Errorf("expected PROMPT_INJECTION, got %s", resp.ThreatType)
		}
	})
}
