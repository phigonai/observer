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
	"strconv"
	"syscall"
	"time"
)

var terminateCgroup func() error

func exitProcess(code int) { os.Exit(code) }

func prepareContainment(command *exec.Cmd, cgroupRoot string, constraints guardianos.Constraints) (func(), error) {
	if constraints.RunAs != nil && os.Geteuid() != 0 {
		return nil, fmt.Errorf("a separate workload identity requires an administrator-owned root supervisor")
	}
	if err := trackDescendants(); err != nil {
		return nil, err
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

// terminateContained stops the managed command and everything it started, and
// reports whether it could confirm that nothing is left running.
func terminateContained(command *exec.Cmd, _ bool) bool {
	confirmed := true
	if terminateCgroup != nil {
		if err := terminateCgroup(); err != nil {
			reportTermination("Phigon Guardian: cgroup containment failed.")
			confirmed = false
		}
	}
	main := 0
	if command.Process != nil {
		main = command.Process.Pid
		_ = syscall.Kill(-main, syscall.SIGKILL)
	}
	// Without a cgroup, descendants that left the process group are found
	// through the subreaper; with one, this confirms cgroup.kill finished.
	return sweepDescendants(main) && confirmed
}
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}
func parentIsAlive(pid int) bool { return os.Getppid() == pid && pid > 1 }
func openExecutionFile(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- Absolute reviewed manifest path; caller verifies its digest before executing.
}

// pinnedExecutablePath returns a path that executes exactly the open file, so
// replacing the reviewed path between hash and exec has no effect. The child
// resolves /proc/self/fd/N before its close-on-exec descriptors close. Scripts
// are excluded: the kernel would hand their interpreter the descriptor path,
// which closes at exec, and the interpreter reads the script by path anyway.
func pinnedExecutablePath(file *os.File) string {
	var header [4]byte
	if _, err := file.ReadAt(header[:], 0); err != nil || string(header[:]) != "\x7fELF" {
		return ""
	}
	return "/proc/self/fd/" + strconv.Itoa(int(file.Fd()))
}
func killExactProcess(_ int, _ time.Time) error {
	return fmt.Errorf("use inventory-verified Unix containment")
}
func dispatchExactProcess(pid int, expected time.Time, _ bool) error {
	return killExactProcess(pid, expected)
}
