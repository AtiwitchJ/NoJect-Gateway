package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLoader(t *testing.T) {
	yamlContent := `
server:
  host: "127.0.0.1"
  port: 9090
  tls:
    enabled: false

auth:
  api_key:
    enabled: true
    header: "X-Custom-Key"
    keys:
      - key: "test-secret-key-1"
        id: "tenant-1"
        roles: ["admin"]

guard_engine:
  endpoint: "http://127.0.0.1:50051"
  timeout_ms: 2500
  fallback_action: "BLOCK"

routes:
  - id: "openai"
    path: "/v1/chat/completions"
    upstream: "https://api.openai.com/v1/chat/completions"
    type: "llm"
    auth_required: true
    guardrails:
      prompt_injection: true
      jailbreak: true
      pii_masking: true

audit:
  driver: "file"
  output_path: "logs/test_audit.log"
  hash_chaining: true
  iso_compliance_mode: true
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "gateway.yaml")
	if err := os.WriteFile(configFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("failed to load valid config: %v", err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Auth.APIKey.Header != "X-Custom-Key" {
		t.Errorf("expected header X-Custom-Key, got %s", cfg.Auth.APIKey.Header)
	}
	if len(cfg.Auth.APIKey.Keys) != 1 {
		t.Fatalf("expected 1 api key registered, got %d", len(cfg.Auth.APIKey.Keys))
	}
	if cfg.GuardEngine.TimeoutMS != 2500 {
		t.Errorf("expected timeout 2500ms, got %d", cfg.GuardEngine.TimeoutMS)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(cfg.Routes))
	}
	if cfg.Routes[0].ID != "openai" {
		t.Errorf("expected route ID openai, got %s", cfg.Routes[0].ID)
	}
	if !cfg.Audit.HashChaining {
		t.Error("expected audit hash chaining enabled")
	}
}
