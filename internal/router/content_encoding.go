package router

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	errDecodedBodyTooLarge      = errors.New("decoded request body exceeds maximum allowed size")
	errMalformedContentEncoding = errors.New("malformed content-encoded request body")
	errUnsupportedEncoding      = errors.New("unsupported content encoding")
)

const maxContentEncodingLayers = 3

// decodeContentEncodedBody returns the representation that the WAF, guard,
// and upstream must all consume. Unknown encodings fail closed so an attacker
// cannot select an encoding that only the upstream understands.
func decodeContentEncodedBody(body []byte, header string, maxBytes int64) ([]byte, bool, error) {
	if strings.TrimSpace(header) == "" {
		return body, false, nil
	}

	parts := strings.Split(header, ",")
	if len(parts) > maxContentEncodingLayers {
		return nil, false, fmt.Errorf("%w: too many encoding layers", errUnsupportedEncoding)
	}

	decoded := body
	didDecode := false
	for i := len(parts) - 1; i >= 0; i-- {
		coding := strings.ToLower(strings.TrimSpace(parts[i]))
		switch coding {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(bytes.NewReader(decoded))
			if err != nil {
				return nil, false, fmt.Errorf("%w: %v", errMalformedContentEncoding, err)
			}
			next, readErr := io.ReadAll(io.LimitReader(zr, maxBytes+1))
			closeErr := zr.Close()
			if readErr != nil {
				return nil, false, fmt.Errorf("%w: %v", errMalformedContentEncoding, readErr)
			}
			if closeErr != nil {
				return nil, false, fmt.Errorf("%w: %v", errMalformedContentEncoding, closeErr)
			}
			if int64(len(next)) > maxBytes {
				return nil, false, errDecodedBodyTooLarge
			}
			decoded = next
			didDecode = true
		default:
			return nil, false, fmt.Errorf("%w: %s", errUnsupportedEncoding, coding)
		}
	}
	return decoded, didDecode, nil
}
