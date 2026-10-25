//go:build windows

package main

import (
	"os"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"github.com/phigonai/observer/go/guardianos"
	"golang.org/x/sys/windows"
)

func TestExactWindowsDispatchRejectsDifferentLifetime(t *testing.T) {
	// A mismatched lifetime must return before either graceful or force dispatch.
	for _, graceful := range []bool{false, true} {
		err := dispatchExactProcess(os.Getpid(), time.Unix(0, 0), graceful)
		if err == nil || err.Error() != "process lifetime changed" {
			t.Fatalf("graceful=%v: expected lifetime rejection, got %v", graceful, err)
		}
	}
}

// Job assignment is irreversible for a process. Only subprocesses created by
// this test enter the test job; the test host and user's applications do not.
func TestWindowsKernelResourceLimits(t *testing.T) {
	const marker = "PHIGON_TEST_JOB_STAGE"
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	switch os.Getenv(marker) {
	case "workload":
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		var returned uint32
		if err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &returned); err != nil {
			t.Fatal(err)
		}
		if info.JobMemoryLimit != 128<<20 || info.BasicLimitInformation.ActiveProcessLimit != 2 {
			t.Fatalf("kernel limits absent: %+v", info)
		}
		var cpu struct {
			Flags uint32
			Rate  uint32
		}
		if err := windows.QueryInformationJobObject(0, windows.JobObjectCpuRateControlInformation, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu)), &returned); err != nil {
			t.Fatal(err)
		}
		if cpu.Flags&5 != 5 || cpu.Rate != 2000 {
			t.Fatalf("CPU hard cap missing: %+v", cpu)
		}
		child := exec.Command(self, "-test.run=^TestWindowsKernelResourceLimits$")
		if err := child.Start(); err == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
			t.Fatal("workload escaped the OS active-process limit")
		}
	case "supervisor":
		child := exec.Command(self, "-test.run=^TestWindowsKernelResourceLimits$")
		child.Env = append(os.Environ(), marker+"=workload")
		cleanup, err := prepareContainment(child, "", guardianos.Constraints{Limits: guardianos.Limits{MaxProcesses: 1, MaxMemoryBytes: 128 << 20, MaxCPUPercent: 20}})
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("workload: %v\n%s", err, output)
		}
	default:
		child := exec.Command(self, "-test.run=^TestWindowsKernelResourceLimits$")
		child.Env = append(os.Environ(), marker+"=supervisor")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("supervisor: %v\n%s", err, output)
		}
	}
}
