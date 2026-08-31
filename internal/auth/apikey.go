package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
)

// APIKeyMetadata defines properties and permissions associated with an API Key.
type APIKeyMetadata struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
	Scopes    []string          `json:"scopes,omitempty"`
	RateLimit int               `json:"rate_limit,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// APIKeyRegistry stores hashed API keys and associated metadata in-memory.
type APIKeyRegistry struct {
	mu   sync.RWMutex
	keys map[string]APIKeyMetadata // key is SHA-256 hex string
}

// NewAPIKeyRegistry creates a new APIKeyRegistry.
func NewAPIKeyRegistry() *APIKeyRegistry {
	return &APIKeyRegistry{
		keys: make(map[string]APIKeyMetadata),
	}
}

func hashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// RegisterKey registers a raw API key (stores only the SHA-256 hash).
func (r *APIKeyRegistry) RegisterKey(rawKey string, meta APIKeyMetadata) {
	r.mu.Lock()
	defer r.mu.Unlock()
	hashed := hashKey(rawKey)
	r.keys[hashed] = meta
}

// Lookup finds metadata for a given raw API key using constant-time comparison.
func (r *APIKeyRegistry) Lookup(rawKey string) (*APIKeyMetadata, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	candidateHash := hashKey(rawKey)

	for h, meta := range r.keys {
		if subtle.ConstantTimeCompare([]byte(h), []byte(candidateHash)) == 1 {
			metaCopy := meta
			return &metaCopy, true
		}
	}
	return nil, false
}

// APIKeyAuthenticator authenticates requests via API key in headers.
type APIKeyAuthenticator struct {
	registry   *APIKeyRegistry
	headerName string
}

// NewAPIKeyAuthenticator returns a new APIKeyAuthenticator.
func NewAPIKeyAuthenticator(registry *APIKeyRegistry, headerName string) *APIKeyAuthenticator {
	if headerName == "" {
		headerName = "X-API-Key"
	}
	return &APIKeyAuthenticator{
		registry:   registry,
		headerName: headerName,
	}
}

// Authenticate extracts and validates API key from custom header or Authorization: Bearer.
func (a *APIKeyAuthenticator) Authenticate(r *http.Request) (*AuthContext, error) {
	rawKey := r.Header.Get(a.headerName)
	if rawKey == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			rawKey = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if rawKey == "" {
		return nil, errors.New("api key missing")
	}

	meta, found := a.registry.Lookup(rawKey)
	if !found {
		return nil, errors.New("invalid api key")
	}

	return &AuthContext{
		Subject:  meta.ID,
		TenantID: meta.TenantID,
		AuthType: AuthTypeAPIKey,
		Roles:    meta.Roles,
		Scopes:   meta.Scopes,
		Metadata: meta.Metadata,
	}, nil
}
