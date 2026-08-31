package auth

import (
	"errors"
	"net/http"
	"strings"
)

// AuthType represents the authentication mechanism used.
type AuthType string

const (
	AuthTypeAPIKey AuthType = "API_KEY"
	AuthTypeJWT    AuthType = "JWT"
	AuthTypeHMAC   AuthType = "HMAC"
)

// AuthContext holds the identity and authorization claims of the authenticated caller.
type AuthContext struct {
	Subject   string            `json:"subject"`
	TenantID  string            `json:"tenant_id,omitempty"`
	AuthType  AuthType          `json:"auth_type"`
	Roles     []string          `json:"roles,omitempty"`
	Scopes    []string          `json:"scopes,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// HasRole checks if the authenticated context contains the specified role.
func (c *AuthContext) HasRole(role string) bool {
	for _, r := range c.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// HasScope checks if the authenticated context contains the specified scope.
func (c *AuthContext) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if strings.EqualFold(s, scope) {
			return true
		}
	}
	return false
}

// Authenticator defines the interface for authenticating incoming HTTP requests.
type Authenticator interface {
	Authenticate(r *http.Request) (*AuthContext, error)
}

// MultiAuthenticator chains multiple authenticators and passes if any succeeds.
type MultiAuthenticator struct {
	authenticators []Authenticator
}

// Option configures MultiAuthenticator.
type Option func(*MultiAuthenticator)

// NewMultiAuthenticator constructs a MultiAuthenticator with options.
func NewMultiAuthenticator(opts ...Option) *MultiAuthenticator {
	m := &MultiAuthenticator{
		authenticators: make([]Authenticator, 0),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// WithAPIKeyAuth adds an API Key authenticator.
func WithAPIKeyAuth(registry *APIKeyRegistry, headerName string) Option {
	return func(m *MultiAuthenticator) {
		m.authenticators = append(m.authenticators, NewAPIKeyAuthenticator(registry, headerName))
	}
}

// WithJWTAuth adds a JWT authenticator.
func WithJWTAuth(jwtAuth *JWTAuthenticator) Option {
	return func(m *MultiAuthenticator) {
		m.authenticators = append(m.authenticators, jwtAuth)
	}
}

// WithHMACAuth adds an HMAC authenticator.
func WithHMACAuth(hmacAuth *HMACAuthenticator) Option {
	return func(m *MultiAuthenticator) {
		m.authenticators = append(m.authenticators, hmacAuth)
	}
}

// Authenticate evaluates each configured authenticator sequentially.
func (m *MultiAuthenticator) Authenticate(r *http.Request) (*AuthContext, error) {
	if len(m.authenticators) == 0 {
		return nil, errors.New("no authenticators configured")
	}

	var lastErr error
	for _, auth := range m.authenticators {
		ctx, err := auth.Authenticate(r)
		if err == nil && ctx != nil {
			return ctx, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("unauthorized: missing or invalid credentials")
}
