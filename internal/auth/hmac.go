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

// HMACConfig holds configuration for HMAC request signature validation.
type HMACConfig struct {
	Secret          []byte
	MaxAge          time.Duration
	SignatureHeader string
	TimestampHeader string
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
	return &HMACAuthenticator{config: config}
}

// Authenticate checks timestamp freshness and calculates HMAC over timestamp and request body.
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

	// Read and buffer the body
	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body for signature verification: %w", err)
		}
		// Restore body for downstream consumers
		r.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	mac := hmac.New(sha256.New, h.config.Secret)
	mac.Write([]byte(fmt.Sprintf("%d:", ts)))
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
