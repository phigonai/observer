package main

import (
	"io"
	"os"
	"os/signal"
	"time"
)

// Console writes can block in the OS. Keep them outside the observer's event
// loop and IO pool; this helper only copies stdin to stdout and cannot launch
// a workload or open a caller-supplied file. Parent loss ends blocked copies.
func runOutputRelay() int {
	if len(os.Args) != 2 {
		return 77
	}
	parent := os.Getppid()
	if !parentIsAlive(parent) {
		return 77
	}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, terminationSignals()...)
	defer signal.Stop(stopped)
	finished := make(chan error, 1)
	go func() { _, err := io.CopyBuffer(os.Stdout, os.Stdin, make([]byte, 32<<10)); finished <- err }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-finished:
			if err != nil {
				return 1
			}
			return 0
		case <-stopped:
			return 77
		case <-ticker.C:
			if !parentIsAlive(parent) {
				return 77
			}
		}
	}
}
