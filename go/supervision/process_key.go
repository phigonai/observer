package supervision

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// ProcessKeyMaterial contains process-lifetime identity, not merely display
// metadata. StartIdentity is a Linux start tick, Windows process-start key, or
// macOS audit-token/start tuple. Execution-boundary membership is deliberately
// excluded because a process can move without starting a new lifetime.
type ProcessKeyMaterial struct {
	MachineID     string
	BootID        string
	ProcessID     uint64
	StartIdentity string
}

// StableProcessKey creates an opaque deterministic process-lifetime key. The
// raw native identifiers stay local; storage and correlation use this digest.
func StableProcessKey(material ProcessKeyMaterial) (string, error) {
	values := []string{
		strings.TrimSpace(material.MachineID),
		strings.TrimSpace(material.BootID),
		strconv.FormatUint(material.ProcessID, 10),
		strings.TrimSpace(material.StartIdentity),
	}
	if values[0] == "" || values[1] == "" || material.ProcessID == 0 ||
		values[3] == "" {
		return "", fmt.Errorf("complete process-lifetime identity is required")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("phigon-process-key-v1\x00"))
	for _, value := range values {
		_, _ = hash.Write([]byte(strconv.Itoa(len(value))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// NewSessionIDs allocates independent opaque identities before an agent
// process is started.
func NewSessionIDs() (agentSessionID, executionBoundaryID string) {
	return uuid.NewString(), uuid.NewString()
}
