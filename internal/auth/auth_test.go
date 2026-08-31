package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAPIKeyAuthenticator(t *testing.T) {
	registry := NewAPIKeyRegistry()
	registry.RegisterKey("valid-secret-key-123", APIKeyMetadata{
		ID:        "client-1",
		TenantID:  "tenant-alpha",
		Roles:     []string{"admin", "user"},
		RateLimit: 100,
	})

	auth := NewMultiAuthenticator(
		WithAPIKeyAuth(registry, "X-API-Key"),
	)

	t.Run("Valid API Key in Header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
		req.Header.Set("X-API-Key", "valid-secret-key-123")

		ctx, err := auth.Authenticate(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ctx == nil {
			t.Fatal("expected non-nil AuthContext")
		}
		if ctx.Subject != "client-1" {
			t.Errorf("expected subject client-1, got %s", ctx.Subject)
		}
		if !ctx.HasRole("admin") {
			t.Error("expected subject to have role 'admin'")
		}
		if ctx.AuthType != AuthTypeAPIKey {
			t.Errorf("expected AuthTypeAPIKey, got %s", ctx.AuthType)
		}
	})

	t.Run("Valid API Key via Bearer Header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer valid-secret-key-123")

		ctx, err := auth.Authenticate(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ctx.Subject != "client-1" {
			t.Errorf("expected client-1, got %s", ctx.Subject)
		}
	})

	t.Run("Invalid API Key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
		req.Header.Set("X-API-Key", "invalid-key-999")

		_, err := auth.Authenticate(req)
		if err == nil {
			t.Fatal("expected error for invalid API key, got nil")
		}
	})

	t.Run("Missing API Key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)

		_, err := auth.Authenticate(req)
		if err == nil {
			t.Fatal("expected error for missing credentials, got nil")
		}
	})
}

func TestJWTAuthenticator(t *testing.T) {
	jwtSecret := []byte("super-secret-jwt-signing-key-32b")
	jwtAuth := NewJWTAuthenticator(JWTConfig{
		Secret:   jwtSecret,
		Issuer:   "https://auth.noject.io",
		Audience: "noject-api",
	})

	auth := NewMultiAuthenticator(
		WithJWTAuth(jwtAuth),
	)

	createToken := func(claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(jwtSecret)
		if err != nil {
			t.Fatalf("failed to sign jwt: %v", err)
		}
		return signed
	}

	t.Run("Valid JWT Token", func(t *testing.T) {
		tokenStr := createToken(jwt.MapClaims{
			"sub":   "user-456",
			"iss":   "https://auth.noject.io",
			"aud":   "noject-api",
			"roles": []interface{}{"developer", "llm-caller"},
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)

		ctx, err := auth.Authenticate(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ctx.Subject != "user-456" {
			t.Errorf("expected subject user-456, got %s", ctx.Subject)
		}
		if !ctx.HasRole("developer") {
			t.Error("expected user-456 to have role 'developer'")
		}
		if ctx.AuthType != AuthTypeJWT {
			t.Errorf("expected AuthTypeJWT, got %s", ctx.AuthType)
		}
	})

	t.Run("Expired JWT Token", func(t *testing.T) {
		tokenStr := createToken(jwt.MapClaims{
			"sub": "user-456",
			"iss": "https://auth.noject.io",
			"aud": "noject-api",
			"exp": time.Now().Add(-1 * time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)

		_, err := auth.Authenticate(req)
		if err == nil {
			t.Fatal("expected error for expired JWT token")
		}
	})

	t.Run("Invalid Audience or Issuer", func(t *testing.T) {
		tokenStr := createToken(jwt.MapClaims{
			"sub": "user-456",
			"iss": "https://attacker.io",
			"aud": "wrong-audience",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)

		_, err := auth.Authenticate(req)
		if err == nil {
			t.Fatal("expected error for invalid issuer/audience")
		}
	})
}

func TestHMACAuthenticator(t *testing.T) {
	hmacSecret := []byte("machine-to-machine-shared-secret")
	hmacAuth := NewHMACAuthenticator(HMACConfig{
		Secret:          hmacSecret,
		MaxAge:          5 * time.Minute,
		SignatureHeader: "X-Signature-SHA256",
		TimestampHeader: "X-Timestamp",
	})

	auth := NewMultiAuthenticator(
		WithHMACAuth(hmacAuth),
	)

	generateHMAC := func(body []byte, ts int64) string {
		mac := hmac.New(sha256.New, hmacSecret)
		mac.Write([]byte(fmt.Sprintf("%d:", ts)))
		mac.Write(body)
		return hex.EncodeToString(mac.Sum(nil))
	}

	t.Run("Valid HMAC Request", func(t *testing.T) {
		body := []byte(`{"message":"hello world"}`)
		ts := time.Now().Unix()
		sig := generateHMAC(body, ts)

		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader(string(body)))
		req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("X-Signature-SHA256", sig)

		ctx, err := auth.Authenticate(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ctx.AuthType != AuthTypeHMAC {
			t.Errorf("expected AuthTypeHMAC, got %s", ctx.AuthType)
		}
	})

	t.Run("Replay Attack (Expired Timestamp)", func(t *testing.T) {
		body := []byte(`{"message":"hello world"}`)
		ts := time.Now().Add(-10 * time.Minute).Unix()
		sig := generateHMAC(body, ts)

		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader(string(body)))
		req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("X-Signature-SHA256", sig)

		_, err := auth.Authenticate(req)
		if err == nil {
			t.Fatal("expected error for expired timestamp (replay attack)")
		}
	})

	t.Run("Tampered Body Signature", func(t *testing.T) {
		body := []byte(`{"message":"hello world"}`)
		ts := time.Now().Unix()
		sig := generateHMAC(body, ts)

		tamperedBody := []byte(`{"message":"tampered content"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/webhook", strings.NewReader(string(tamperedBody)))
		req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("X-Signature-SHA256", sig)

		_, err := auth.Authenticate(req)
		if err == nil {
			t.Fatal("expected error for tampered body")
		}
	})
}
