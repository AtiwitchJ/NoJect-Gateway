package guardclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Policies configures which guardrail checks to run.
type Policies struct {
	EnablePromptInjection bool    `json:"enable_prompt_injection"`
	EnableJailbreak       bool    `json:"enable_jailbreak"`
	EnablePIIMasking      bool    `json:"enable_pii_masking"`
	EnableAgenticSentinel bool    `json:"enable_agentic_sentinel"`
	SensitivityThreshold  float64 `json:"sensitivity_threshold"`
}

// DefaultPolicies provides secure baseline policies. AgenticSentinel is
// deliberately excluded — it is a real per-request LLM API call (cost +
// 1-5s latency), so it stays opt-in per route rather than a default-on
// guardrail alongside the free/local ones.
func DefaultPolicies() Policies {
	return Policies{
		EnablePromptInjection: true,
		EnableJailbreak:       true,
		EnablePIIMasking:      true,
		SensitivityThreshold:  0.7,
	}
}

// InspectRequestPayload is sent to the Python Guard Engine.
type InspectRequestPayload struct {
	TraceID  string            `json:"trace_id"`
	Route    string            `json:"route"`
	Prompt   string            `json:"prompt"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Policies Policies          `json:"policies"`
}

// InspectRequestResponse is returned by the Python Guard Engine.
type InspectRequestResponse struct {
	Allowed         bool    `json:"allowed"`
	SanitizedPrompt string  `json:"sanitized_prompt"`
	ThreatType      string  `json:"threat_type"`
	RiskLevel       string  `json:"risk_level"`
	Confidence      float64 `json:"confidence"`
	Reason          string  `json:"reason"`
}

// InspectOutputPayload is sent to inspect upstream LLM responses.
type InspectOutputPayload struct {
	TraceID      string   `json:"trace_id"`
	ResponseText string   `json:"response_text"`
	CanaryTokens []string `json:"canary_tokens,omitempty"`
}

// InspectOutputResponse is returned when inspecting responses.
type InspectOutputResponse struct {
	Allowed           bool   `json:"allowed"`
	SanitizedResponse string `json:"sanitized_response"`
	ThreatType        string `json:"threat_type"`
	Reason            string `json:"reason"`
}

// Client communicates with the Python AI Guard Engine.
type Client struct {
	baseURL        string
	httpClient     *http.Client
	fallbackAction string // "BLOCK" or "ALLOW"
}

// Config configures the Guard Client.
type Config struct {
	Endpoint       string
	Timeout        time.Duration
	FallbackAction string
}

// NewClient creates a new Guard Client.
func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.FallbackAction == "" {
		cfg.FallbackAction = "BLOCK"
	}

	return &Client{
		baseURL: cfg.Endpoint,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		fallbackAction: cfg.FallbackAction,
	}
}

// InspectRequest sends input prompt to AI Guard Engine for safety classification.
func (c *Client) InspectRequest(ctx context.Context, payload InspectRequestPayload) (*InspectRequestResponse, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inspect payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/inspect/request", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if c.fallbackAction == "ALLOW" {
			return &InspectRequestResponse{
				Allowed:         true,
				SanitizedPrompt: payload.Prompt,
				ThreatType:      "GUARD_UNAVAILABLE",
				Reason:          fmt.Sprintf("guard engine unavailable, fallback ALLOW: %v", err),
			}, nil
		}
		return nil, fmt.Errorf("guard engine communication failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("guard engine returned status %d: %s", resp.StatusCode, string(body))
	}

	var inspectResp InspectRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&inspectResp); err != nil {
		return nil, fmt.Errorf("failed to decode guard response: %w", err)
	}

	return &inspectResp, nil
}

// InspectResponse sends output text to AI Guard Engine for canary/secret leak checks.
func (c *Client) InspectResponse(ctx context.Context, payload InspectOutputPayload) (*InspectOutputResponse, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal output payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/inspect/response", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guard engine output inspection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("guard engine output inspection returned non-200 status")
	}

	var outResp InspectOutputResponse
	if err := json.NewDecoder(resp.Body).Decode(&outResp); err != nil {
		return nil, fmt.Errorf("failed to decode guard output response: %w", err)
	}

	return &outResp, nil
}
