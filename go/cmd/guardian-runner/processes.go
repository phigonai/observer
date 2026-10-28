package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// processEntry is one process in the __processes listing. The observer
// derives process identities from the same fields of Win32_Process when this
// listing is unavailable.
type processEntry struct {
	PID       uint32 `json:"pid"`
	ParentPID uint32 `json:"ppid"`
	// CreatedMs is the creation time in Unix milliseconds, truncated as
	// PowerShell serializes Win32_Process.CreationDate. Zero is omitted.
	CreatedMs int64  `json:"created_ms,omitempty"`
	Name      string `json:"name"`
	// Path is the executable's Win32 path. It is empty when the process
	// cannot be opened with limited query rights.
	Path string `json:"path,omitempty"`
}

// listProcesses writes every process as one JSON array. It only reads
// process information and exits; it never waits for input.
func listProcesses(output io.Writer) int {
	entries, err := processEntries()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Phigon Guardian: process listing is unavailable.")
		return 1
	}
	if err := json.NewEncoder(output).Encode(entries); err != nil {
		return 1
	}
	return 0
}
