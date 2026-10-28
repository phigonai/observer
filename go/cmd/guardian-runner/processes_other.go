//go:build !windows

package main

import "errors"

// Linux and macOS discovery reads the process table with ps.
func processEntries() ([]processEntry, error) {
	return nil, errors.New("process listing is only provided on Windows")
}
