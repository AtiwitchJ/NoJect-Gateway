package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig defines verification parameters for JWT tokens.
type JWTConfig struct {
	Secret        []byte
	Issuer        string
	Audience      string
	AllowedAlgs   []string
}

// JWTAuthenticator validates JWT tokens from the Authorization header.
type JWTAuthenticator struct {
	config JWTConfig
}

// NewJWTAuthenticator creates a new JWTAuthenticator.
func NewJWTAuthenticator(config JWTConfig) *JWTAuthenticator {
	if len(config.AllowedAlgs) == 0 {
		config.AllowedAlgs = []string{"HS256", "HS384", "HS512", "RS256", "ES256"}
	}
	return &JWTAuthenticator{config: config}
}

// Authenticate extracts and validates JWT from Authorization: Bearer <token>.
func (j *JWTAuthenticator) Authenticate(r *http.Request) (*AuthContext, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("missing or invalid authorization header")
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		return nil, errors.New("empty bearer token")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			return j.config.Secret, nil
		}
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	})

	if err != nil {
		return nil, fmt.Errorf("jwt validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid jwt token")
	}

	// Validate Issuer if configured
	if j.config.Issuer != "" {
		iss, _ := claims.GetIssuer()
		if iss != j.config.Issuer {
			return nil, fmt.Errorf("invalid issuer: expected %s, got %s", j.config.Issuer, iss)
		}
	}

	// Validate Audience if configured
	if j.config.Audience != "" {
		aud, _ := claims.GetAudience()
		foundAud := false
		for _, a := range aud {
			if a == j.config.Audience {
				foundAud = true
				break
			}
		}
		if !foundAud {
			return nil, fmt.Errorf("invalid audience: expected %s", j.config.Audience)
		}
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		sub = "anonymous"
	}

	var roles []string
	if rawRoles, ok := claims["roles"]; ok {
		if roleSlice, ok := rawRoles.([]interface{}); ok {
			for _, r := range roleSlice {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}

	var scopes []string
	if rawScopes, ok := claims["scopes"]; ok {
		if scopeSlice, ok := rawScopes.([]interface{}); ok {
			for _, s := range scopeSlice {
				if sc, ok := s.(string); ok {
					scopes = append(scopes, sc)
				}
			}
		}
	}

	return &AuthContext{
		Subject:  sub,
		AuthType: AuthTypeJWT,
		Roles:    roles,
		Scopes:   scopes,
	}, nil
}
