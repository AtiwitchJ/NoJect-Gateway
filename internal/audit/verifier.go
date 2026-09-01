package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// VerificationResult contains the cryptographic audit chain verification report.
type VerificationResult struct {
	Valid         bool   `json:"valid"`
	TotalRecords  int    `json:"total_records"`
	BrokenAtIndex int    `json:"broken_at_index,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// VerifyChain parses all records from the reader and verifies the hash chain integrity.
func VerifyChain(r io.Reader) (*VerificationResult, error) {
	return verifyChain(r, false)
}

// VerifyLatestCheckpoint verifies the event chain and, for checkpoint-enabled
// logs, requires its final non-empty record to be a valid checkpoint. It
// retains verification compatibility for legacy logs written before trailers
// were introduced.
func VerifyLatestCheckpoint(r io.Reader) (*VerificationResult, error) {
	return verifyChain(r, true)
}

func verifyChain(r io.Reader, requireTerminalCheckpoint bool) (*VerificationResult, error) {
	scanner := bufio.NewScanner(r)
	expectedPrevHash := GenesisHash
	recordIndex := 0
	terminalCheckpoint := false
	hasCheckpointProtocol := false

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &header); err != nil {
			return &VerificationResult{
				Valid:         false,
				TotalRecords:  recordIndex,
				BrokenAtIndex: recordIndex,
				Reason:        fmt.Sprintf("corrupted JSON on record %d: %v", recordIndex, err),
			}, nil
		}

		if header.Type == checkpointType {
			var checkpoint Checkpoint
			if err := json.Unmarshal([]byte(line), &checkpoint); err != nil {
				return &VerificationResult{Valid: false, TotalRecords: recordIndex, BrokenAtIndex: recordIndex, Reason: fmt.Sprintf("corrupted checkpoint: %v", err)}, nil
			}
			if checkpoint.RecordCount != recordIndex || checkpoint.TipHash != expectedPrevHash || checkpoint.CheckpointHash != CalculateCheckpointHash(checkpoint) {
				return &VerificationResult{Valid: false, TotalRecords: recordIndex, BrokenAtIndex: recordIndex, Reason: "invalid audit checkpoint commitment"}, nil
			}
			terminalCheckpoint = true
			continue
		}
		terminalCheckpoint = false

		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return &VerificationResult{Valid: false, TotalRecords: recordIndex, BrokenAtIndex: recordIndex, Reason: fmt.Sprintf("corrupted JSON on record %d: %v", recordIndex, err)}, nil
		}
		if ev.CheckpointVersion > 0 {
			hasCheckpointProtocol = true
		}

		// 1. Verify previous hash pointer
		if ev.PrevRecordHash != expectedPrevHash {
			return &VerificationResult{
				Valid:         false,
				TotalRecords:  recordIndex,
				BrokenAtIndex: recordIndex,
				Reason: fmt.Sprintf("hash link mismatch at record %d: expected prev_hash %s, found %s",
					recordIndex, expectedPrevHash, ev.PrevRecordHash),
			}, nil
		}

		// 2. Verify current record content hash
		computedHash := CalculateRecordHash(ev)
		if ev.RecordHash != computedHash {
			return &VerificationResult{
				Valid:         false,
				TotalRecords:  recordIndex,
				BrokenAtIndex: recordIndex,
				Reason: fmt.Sprintf("payload tampering at record %d: expected hash %s, computed %s",
					recordIndex, ev.RecordHash, computedHash),
			}, nil
		}

		expectedPrevHash = ev.RecordHash
		recordIndex++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error during verification: %w", err)
	}
	if requireTerminalCheckpoint && hasCheckpointProtocol && !terminalCheckpoint {
		return &VerificationResult{Valid: false, TotalRecords: recordIndex, BrokenAtIndex: recordIndex, Reason: "missing terminal audit checkpoint"}, nil
	}

	return &VerificationResult{
		Valid:        true,
		TotalRecords: recordIndex,
	}, nil
}
