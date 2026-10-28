package main

import (
	"encoding/json"
	"io"
	"time"
)

// treeWait bounds how long the runner waits for the stopped tree to exit.
// The observer's own timeout for this helper is longer.
const treeWait = 5 * time.Second

// maxTreeMembers bounds the descendants one request can touch.
const maxTreeMembers = 1024

// treeReport is the only output of --kill-pid with --tree. Outcome values:
//
//	dispatched            the request was sent; the counts describe the result
//	stale                 the PID now belongs to a different process lifetime
//	exited                the exact process had already exited
//	access_denied         the OS refused access to the exact process
//	graceful_unsupported  graceful stop requested but the process has no
//	                      window Windows can ask to close; nothing was sent
//	self_target           the target is the observer or this helper
//	invalid               malformed request
//	unsupported           this platform uses the observer's own executor
//	failed                the OS call failed; see Error
type treeReport struct {
	Outcome            string `json:"outcome"`
	RootRunning        bool   `json:"root_running"`
	Descendants        int    `json:"descendants"`
	DescendantsRunning int    `json:"descendants_running"`
	DescendantsDenied  int    `json:"descendants_denied"`
	Error              string `json:"error,omitempty"`
}

func writeTreeReport(output io.Writer, report treeReport) int {
	if len(report.Error) > 64 {
		report.Error = report.Error[:64]
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return 77
	}
	return 0
}
