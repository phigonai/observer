//go:build windows

package main

import (
	"context"
	"fmt"
	"github.com/phigonai/observer/go/guardianos"
	"golang.org/x/sys/windows"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"
)

var executionJob windows.Handle

func exitProcess(code int) {
	if code < 0 || int64(code) > math.MaxUint32 {
		code = 1
	}
	if executionJob != 0 {
		// Explicit termination also covers a copied job handle keeping the object
		// alive. Kill-on-close remains the backstop for unexpected supervisor exit.
		_ = windows.TerminateJobObject(executionJob, uint32(code))
	}
	os.Exit(code)
}

func prepareContainment(_ *exec.Cmd, cgroupRoot string, constraints guardianos.Constraints) (func(), error) {
	if cgroupRoot != "" {
		return nil, fmt.Errorf("cgroups require Linux")
	}
	if constraints.Limits.MaxProcesses < 0 || constraints.Limits.MaxProcesses > 65535 || constraints.Limits.MaxCPUPercent < 0 || constraints.Limits.MaxCPUPercent > 100 {
		return nil, fmt.Errorf("invalid Windows job limits")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if constraints.Limits.MaxProcesses > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		// One extra member is the trusted native supervisor itself.
		info.BasicLimitInformation.ActiveProcessLimit = uint32(constraints.Limits.MaxProcesses + 1)
	}
	if constraints.Limits.MaxMemoryBytes > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		info.JobMemoryLimit = uintptr(constraints.Limits.MaxMemoryBytes)
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { // #nosec G103 -- Win32 ABI requires the typed structure address and exact size for this synchronous call.
		_ = windows.CloseHandle(job)
		return nil, err
	}
	if constraints.Limits.MaxCPUPercent > 0 {
		// JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | HARD_CAP. Rate is in 1/100 percent.
		rate := struct {
			Flags uint32
			Rate  uint32
		}{0x1 | 0x4, uint32(constraints.Limits.MaxCPUPercent * 100)}
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectCpuRateControlInformation, uintptr(unsafe.Pointer(&rate)), uint32(unsafe.Sizeof(rate))); err != nil { // #nosec G103 -- Win32 ABI requires the typed CPU-rate structure address and exact size.
			_ = windows.CloseHandle(job)
			return nil, err
		}
	}
	// Assign this supervisor before spawning: children enter the job at creation,
	// avoiding the run-before-assignment race. The handle is not inheritable.
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	executionJob = job
	// Deliberately keep the sole handle until process exit. Closing it here would
	// terminate the supervisor before it can preserve the command's exit status.
	return func() {}, nil
}
func terminateContained(_ *exec.Cmd, _ bool) {}
func terminationSignals() []os.Signal        { return []os.Signal{os.Interrupt} }
func parentIsAlive(pid int) bool {
	if pid <= 0 || int64(pid) > math.MaxUint32 {
		return false
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	state, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && state == uint32(windows.WAIT_TIMEOUT)
}
func openExecutionFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
func dispatchExactProcess(pid int, expected time.Time, graceful bool) error {
	if pid <= 4 || int64(pid) > math.MaxUint32 {
		return fmt.Errorf("invalid Windows process ID")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return err
	}
	if created.Nanoseconds()/int64(time.Millisecond) != expected.UnixMilli() {
		return fmt.Errorf("process lifetime changed")
	}
	if graceful {
		// Keep the verified process object open until dispatch completes. Windows
		// cannot recycle its PID while this handle is held.
		state, err := windows.WaitForSingleObject(handle, 0)
		if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("process already stopped")
		}
		directory, err := windows.GetSystemDirectory()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, filepath.Join(directory, "taskkill.exe"), "/PID", strconv.Itoa(pid)).Run() // #nosec G204 -- OS-owned executable, separate decimal PID argument, verified process lifetime, no shell.
	}
	if err := windows.TerminateProcess(handle, 77); err != nil {
		return err
	}
	state, err := windows.WaitForSingleObject(handle, 5000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("process did not stop")
	}
	return nil
}
