//go:build linux

package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/phigonai/observer/go/guardianos"
	"github.com/phigonai/observer/go/linuxsupervisor"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

var terminateCgroup func() error

func exitProcess(code int) { os.Exit(code) }

func prepareContainment(command *exec.Cmd, cgroupRoot string, constraints guardianos.Constraints) (func(), error) {
	if constraints.RunAs != nil && os.Geteuid() != 0 {
		return nil, fmt.Errorf("a separate workload identity requires an administrator-owned root supervisor")
	}
	if cgroupRoot == "" {
		runtime.LockOSThread()
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		return func() {}, nil
	}
	// PR_SET_PDEATHSIG is tied to the creating OS thread. Keep that thread
	// alive until the managed command has exited, even when Go reschedules work.
	runtime.LockOSThread()
	helper, err := os.Executable()
	if err != nil {
		return nil, err
	}
	launcher, err := linuxsupervisor.NewLauncher(linuxsupervisor.Config{CgroupRoot: cgroupRoot, ProcRoot: "/proc", MachineID: "guardian-managed-execution", HelperPath: helper})
	if err != nil {
		return nil, err
	}
	boundary, err := launcher.CreateBoundary("guardian-" + uuid.NewString())
	if err != nil {
		return nil, err
	}
	if err := launcher.SetResourceLimits(boundary, constraints.Limits); err != nil {
		_ = launcher.RemoveBoundary(boundary)
		return nil, err
	}
	if err := launcher.ConfigureCommand(boundary, command); err != nil {
		_ = launcher.RemoveBoundary(boundary)
		return nil, err
	}
	if constraints.RunAs != nil {
		command.SysProcAttr.Credential = &syscall.Credential{Uid: constraints.RunAs.UID, Gid: constraints.RunAs.GID, Groups: []uint32{}}
	}
	terminateCgroup = func() error { return launcher.KillBoundary(boundary) }
	return func() {
		_ = launcher.KillBoundary(boundary)
		for range 30 {
			if launcher.RemoveBoundary(boundary) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		reportTermination("Phigon Guardian: empty cgroup cleanup needs administrator attention.")
	}, nil
}
func terminateContained(command *exec.Cmd, _ bool) {
	if terminateCgroup != nil {
		if err := terminateCgroup(); err != nil {
			reportTermination("Phigon Guardian: cgroup containment failed.")
		}
	}
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}
func parentIsAlive(pid int) bool { return os.Getppid() == pid && pid > 1 }
func openExecutionFile(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- Absolute reviewed manifest path; caller verifies its digest before executing.
}
func killExactProcess(_ int, _ time.Time) error {
	return fmt.Errorf("use inventory-verified Unix containment")
}
func dispatchExactProcess(pid int, expected time.Time, _ bool) error {
	return killExactProcess(pid, expected)
}
