//go:build darwin

package main

import (
	"fmt"
	"github.com/phigonai/observer/go/guardianos"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func exitProcess(code int) { os.Exit(code) }

func prepareContainment(command *exec.Cmd, cgroupRoot string, _ guardianos.Constraints) (func(), error) {
	if cgroupRoot != "" {
		return nil, fmt.Errorf("cgroups require Linux")
	}
	if err := trackDescendants(); err != nil {
		return nil, err
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return func() {}, nil
}

// terminateContained stops the managed command and everything it started, and
// reports whether it could confirm that nothing is left running.
func terminateContained(command *exec.Cmd, _ bool) bool {
	main := 0
	if command.Process != nil {
		main = command.Process.Pid
		_ = syscall.Kill(-main, syscall.SIGKILL)
	}
	// A descendant that called setsid left the process group; stop it too.
	return sweepDescendants(main)
}
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}
func parentIsAlive(pid int) bool                      { return os.Getppid() == pid && pid > 1 }
func openExecutionFile(path string) (*os.File, error) { return os.Open(path) }

// macOS cannot execute an open file (no fexecve or execveat), and a private
// copy would break programs that find their libraries next to themselves while
// staying writable by the same user. The path is executed as reviewed.
func pinnedExecutablePath(_ *os.File) string { return "" }
func killExactProcess(_ int, _ time.Time) error {
	return fmt.Errorf("use the Unix inventory-verified executor")
}
func dispatchExactProcess(pid int, expected time.Time, _ bool) error {
	return killExactProcess(pid, expected)
}
