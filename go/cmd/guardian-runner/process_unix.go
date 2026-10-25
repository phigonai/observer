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
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return func() {}, nil
}
func terminateContained(command *exec.Cmd, _ bool) {
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}
func parentIsAlive(pid int) bool                      { return os.Getppid() == pid && pid > 1 }
func openExecutionFile(path string) (*os.File, error) { return os.Open(path) }
func killExactProcess(_ int, _ time.Time) error {
	return fmt.Errorf("use the Unix inventory-verified executor")
}
func dispatchExactProcess(pid int, expected time.Time, _ bool) error {
	return killExactProcess(pid, expected)
}
