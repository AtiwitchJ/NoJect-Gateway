package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"noject/internal/router"
)

// ServerConfig defines HTTP listening parameters.
type ServerConfig struct {
	Host string    `yaml:"host"`
	Port int       `yaml:"port"`
	TLS  TLSConfig `yaml:"tls"`
}

// TLSConfig defines HTTPS TLS settings.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// APIKeyEntry defines a pre-configured API key with metadata.
type APIKeyEntry struct {
	Key       string   `yaml:"key"`
	ID        string   `yaml:"id"`
	TenantID  string   `yaml:"tenant_id"`
	Roles     []string `yaml:"roles"`
	RateLimit int      `yaml:"rate_limit"`
}

// APIKeyConfig defines API Key authentication settings.
type APIKeyConfig struct {
	Enabled bool          `yaml:"enabled"`
	Header  string        `yaml:"header"`
	Keys    []APIKeyEntry `yaml:"keys"`
}

// JWTConfig defines JWT authentication settings.
type JWTConfig struct {
	Enabled  bool   `yaml:"enabled"`
	JWKSURL  string `yaml:"jwks_url"`
	Secret   string `yaml:"secret"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
}

// AuthConfig aggregates authentication methods.
type AuthConfig struct {
	APIKey APIKeyConfig `yaml:"api_key"`
	JWT    JWTConfig    `yaml:"jwt"`
}

// GuardEngineConfig defines communication settings for the Python AI Guard Engine.
type GuardEngineConfig struct {
	Endpoint       string `yaml:"endpoint"`
	TimeoutMS      int    `yaml:"timeout_ms"`
	FallbackAction string `yaml:"fallback_action"` // "BLOCK" or "ALLOW"
}

// AuditConfig defines ISO 27001 audit logging settings.
type AuditConfig struct {
	Driver            string `yaml:"driver"` // "file"
	OutputPath        string `yaml:"output_path"`
	HashChaining      bool   `yaml:"hash_chaining"`
	ISOComplianceMode bool   `yaml:"iso_compliance_mode"`
}

// Config represents the complete NoJect Gateway configuration tree.
type Config struct {
	Version     string            `yaml:"version"`
	Server      ServerConfig      `yaml:"server"`
	Auth        AuthConfig        `yaml:"auth"`
	GuardEngine GuardEngineConfig `yaml:"guard_engine"`
	Routes      []router.Route    `yaml:"routes"`
	Audit       AuditConfig       `yaml:"audit"`
}

// DefaultConfig returns a secure default configuration.
func DefaultConfig() Config {
	return Config{
		Version: "1.0",
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Auth: AuthConfig{
			APIKey: APIKeyConfig{
				Enabled: true,
				Header:  "X-API-Key",
			},
		},
		GuardEngine: GuardEngineConfig{
			Endpoint:       "http://localhost:50051",
			TimeoutMS:      3000,
			FallbackAction: "BLOCK",
		},
		Audit: AuditConfig{
			Driver:            "file",
			OutputPath:        "logs/audit.log",
			HashChaining:      true,
			ISOComplianceMode: true,
		},
	}
}

// Load reads and parses a YAML configuration file.
func Load(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate checks for configuration constraints and errors.
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return errors.New("server port must be between 1 and 65535")
	}

	if len(c.Routes) == 0 {
		return errors.New("at least one route must be configured")
	}

	for idx, r := range c.Routes {
		if r.Path == "" {
			return fmt.Errorf("route #%d path cannot be empty", idx)
		}
		if r.Upstream == "" {
			return fmt.Errorf("route #%d upstream url cannot be empty", idx)
		}
	}

	return nil
}
