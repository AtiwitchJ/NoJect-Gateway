package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// CalculateRecordHash creates a deterministic SHA-256 hash for an Event.
func CalculateRecordHash(e Event) string {
	h := sha256.New()
	// Format deterministic payload
	payload := fmt.Sprintf(
		"prev:%s|ts:%d|trace:%s|client:%s|ip:%s|route:%s|act:%s|threat:%s|sev:%s|conf:%.4f|reason:%s|rule:%s",
		e.PrevRecordHash,
		e.Timestamp.UTC().UnixNano(),
		e.TraceID,
		e.ClientID,
		e.ClientIP,
		e.Route,
		e.Action,
		e.ThreatCategory,
		e.Severity,
		e.Confidence,
		e.Reason,
		e.MatchedRule,
	)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// RecoverLastHash reads the file from the start and returns the record_hash of the final line.
func RecoverLastHash(r io.ReadSeeker) (string, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(r)
	lastHash := GenesisHash

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return lastHash, err
		}
		lastHash = ev.RecordHash
	}

	return lastHash, scanner.Err()
}
