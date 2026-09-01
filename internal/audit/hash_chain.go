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
	if e.CheckpointVersion > 0 {
		payload += fmt.Sprintf("|checkpoint_version:%d", e.CheckpointVersion)
	}
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// CalculateCheckpointHash creates a deterministic commitment to the current
// event-chain tip and total event count.
func CalculateCheckpointHash(c Checkpoint) string {
	h := sha256.New()
	payload := fmt.Sprintf("checkpoint:v1|count:%d|tip:%s", c.RecordCount, c.TipHash)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// RecoverLastHash reads the file from the start and returns the record_hash of the final line.
func RecoverLastHash(r io.ReadSeeker) (string, error) {
	lastHash, _, err := RecoverLogState(r)
	return lastHash, err
}

// RecoverLogState reads event records while ignoring checkpoint trailers.
func RecoverLogState(r io.ReadSeeker) (string, int, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}

	scanner := bufio.NewScanner(r)
	lastHash := GenesisHash
	recordCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &header); err != nil {
			return lastHash, recordCount, err
		}
		if header.Type == checkpointType {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return lastHash, recordCount, err
		}
		lastHash = ev.RecordHash
		recordCount++
	}

	return lastHash, recordCount, scanner.Err()
}
