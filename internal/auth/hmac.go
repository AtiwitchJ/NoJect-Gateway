package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// MaxSignedBodyBytes caps how much request body the HMAC verifier will read
// into memory. Signature verification runs before any other guardrail, on
// unauthenticated input, so an unbounded io.ReadAll here is a pre-auth
// memory-exhaustion vector: an attacker needs no valid credential to make
// the gateway buffer an arbitrarily large body.
const MaxSignedBodyBytes = 32 << 20 // 32 MiB

// HMACConfig holds configuration for HMAC request signature validation.
type HMACConfig struct {
	Secret          []byte
	MaxAge          time.Duration
	SignatureHeader string
	TimestampHeader string
	// MaxBodyBytes bounds the body read during verification.
	// Defaults to MaxSignedBodyBytes when zero.
	MaxBodyBytes int64
}

// HMACAuthenticator validates HMAC signatures on HTTP requests.
type HMACAuthenticator struct {
	config HMACConfig
}

// NewHMACAuthenticator creates a new HMACAuthenticator.
func NewHMACAuthenticator(config HMACConfig) *HMACAuthenticator {
	if config.MaxAge == 0 {
		config.MaxAge = 5 * time.Minute
	}
	if config.SignatureHeader == "" {
		config.SignatureHeader = "X-Signature-SHA256"
	}
	if config.TimestampHeader == "" {
		config.TimestampHeader = "X-Timestamp"
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxSignedBodyBytes
	}
	return &HMACAuthenticator{config: config}
}

// SigningString builds the canonical string that both client and server sign.
//
// The signature MUST bind the request's method, path and query — not just
// the timestamp and body. Signing only "<ts>:<body>" makes a signature
// portable across endpoints: a signature captured from a harmless call
// (POST /api/v1/comment with body "{}") stays valid for any other route
// taking the same body (POST /api/v1/account/reset) for the whole MaxAge
// window. Binding the verb and target makes each signature usable only for
// the exact request it was issued for.
//
// Format: "<method>\n<path>\n<rawquery>\n<unix-ts>\n" followed by raw body.
func SigningString(method, path, rawQuery string, ts int64) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%d\n", method, path, rawQuery, ts))
}

// Authenticate checks timestamp freshness and verifies the HMAC over the
// canonical request representation (method, path, query, timestamp, body).
func (h *HMACAuthenticator) Authenticate(r *http.Request) (*AuthContext, error) {
	sigHeader := r.Header.Get(h.config.SignatureHeader)
	if sigHeader == "" {
		return nil, errors.New("missing signature header")
	}

	tsHeader := r.Header.Get(h.config.TimestampHeader)
	if tsHeader == "" {
		return nil, errors.New("missing timestamp header")
	}

	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return nil, errors.New("invalid timestamp format")
	}

	reqTime := time.Unix(ts, 0)
	now := time.Now()
	diff := now.Sub(reqTime)
	if diff < 0 {
		diff = -diff
	}

	if diff > h.config.MaxAge {
		return nil, errors.New("timestamp expired (potential replay attack)")
	}

	// Read and buffer the body, bounded — this runs pre-auth, so an
	// unbounded read is a memory-exhaustion vector (see MaxSignedBodyBytes).
	var body []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, h.config.MaxBodyBytes+1)
		body, err = io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("failed to read body for signature verification: %w", err)
		}
		if int64(len(body)) > h.config.MaxBodyBytes {
			return nil, errors.New("request body exceeds maximum signable size")
		}
		// Restore body for downstream consumers
		r.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	mac := hmac.New(sha256.New, h.config.Secret)
	mac.Write(SigningString(r.Method, r.URL.Path, r.URL.RawQuery, ts))
	mac.Write(body)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(sigHeader), []byte(expectedSig)) != 1 {
		return nil, errors.New("invalid signature")
	}

	return &AuthContext{
		Subject:  "hmac-client",
		AuthType: AuthTypeHMAC,
		Roles:    []string{"machine"},
	}, nil
}
