package router

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
)

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}
	return compressed.Bytes()
}

func TestDecodeContentEncodedBody(t *testing.T) {
	payload := []byte(`{"messages":[{"content":"hello"}]}`)

	t.Run("gzip", func(t *testing.T) {
		got, decoded, err := decodeContentEncodedBody(gzipBytes(t, payload), "gzip", 1024)
		if err != nil || !decoded || !bytes.Equal(got, payload) {
			t.Fatalf("got decoded=%v body=%q err=%v", decoded, got, err)
		}
	})

	t.Run("nested gzip", func(t *testing.T) {
		got, decoded, err := decodeContentEncodedBody(gzipBytes(t, gzipBytes(t, payload)), "gzip, gzip", 1024)
		if err != nil || !decoded || !bytes.Equal(got, payload) {
			t.Fatalf("got decoded=%v body=%q err=%v", decoded, got, err)
		}
	})

	t.Run("unsupported fails closed", func(t *testing.T) {
		_, _, err := decodeContentEncodedBody(payload, "br", 1024)
		if !errors.Is(err, errUnsupportedEncoding) {
			t.Fatalf("expected unsupported encoding, got %v", err)
		}
	})

	t.Run("malformed gzip", func(t *testing.T) {
		_, _, err := decodeContentEncodedBody([]byte("not gzip"), "gzip", 1024)
		if !errors.Is(err, errMalformedContentEncoding) {
			t.Fatalf("expected malformed encoding, got %v", err)
		}
	})

	t.Run("decompression bomb bounded", func(t *testing.T) {
		_, _, err := decodeContentEncodedBody(gzipBytes(t, []byte(strings.Repeat("A", 2048))), "gzip", 1024)
		if !errors.Is(err, errDecodedBodyTooLarge) {
			t.Fatalf("expected decoded size error, got %v", err)
		}
	})
}
