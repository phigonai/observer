//go:build !windows

package main

import "time"

// Linux and macOS process trees are signalled by the observer after an exact
// process-table snapshot; the native helper is only needed on Windows.
func dispatchExactTree(_ int, _ time.Time, _ bool, _ time.Duration) treeReport {
	return treeReport{Outcome: "unsupported"}
}

// Timed-out commands on Linux and macOS run in their own process group,
// which the observer signals directly.
func dispatchOwnChildTree(_ int, _ int, _ time.Duration) treeReport {
	return treeReport{Outcome: "unsupported"}
}
