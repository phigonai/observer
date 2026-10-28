//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const treeStage = "PHIGON_TEST_TREE_STAGE"

// The test stops only processes it starts itself: a copy of this test binary
// (root) that starts one more copy (leaf), both idling until stopped.
func TestExactWindowsTreeStopsOnlyItsOwnDescendants(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	switch os.Getenv(treeStage) {
	case "leaf":
		time.Sleep(time.Minute)
		return
	case "root":
		leaf := exec.Command(self, "-test.run=^TestExactWindowsTreeStopsOnlyItsOwnDescendants$")
		leaf.Env = append(os.Environ(), treeStage+"=leaf")
		if err := leaf.Start(); err != nil {
			os.Exit(3)
		}
		fmt.Printf("LEAF %d\n", leaf.Process.Pid)
		time.Sleep(time.Minute)
		return
	}

	root := exec.Command(self, "-test.run=^TestExactWindowsTreeStopsOnlyItsOwnDescendants$")
	root.Env = append(os.Environ(), treeStage+"=root")
	stdout, err := root.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Process.Kill(); _ = root.Wait() })
	scanner := bufio.NewScanner(stdout)
	leafPID := 0
	for scanner.Scan() {
		if value, found := strings.CutPrefix(scanner.Text(), "LEAF "); found {
			leafPID, _ = strconv.Atoi(value)
			break
		}
	}
	if leafPID == 0 {
		t.Fatal("test root did not start its leaf")
	}
	leaf, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(leafPID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(leaf) }()
	t.Cleanup(func() { _ = windows.TerminateProcess(leaf, 1) })
	rootHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(root.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	created, err := creationTime(rootHandle)
	_ = windows.CloseHandle(rootHandle)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Unix(0, created)

	if report := dispatchExactTree(root.Process.Pid, startedAt.Add(-time.Second), false, time.Second); report.Outcome != "stale" {
		t.Fatalf("a different lifetime must not be touched: %+v", report)
	}
	// Test binaries have no window, like console agents: nothing may be sent.
	report := dispatchExactTree(root.Process.Pid, startedAt, true, time.Second)
	if report.Outcome != "graceful_unsupported" || !running(leaf) {
		t.Fatalf("graceful stop of a windowless tree must send nothing: %+v", report)
	}
	report = dispatchExactTree(root.Process.Pid, startedAt, false, 5*time.Second)
	if report.Outcome != "dispatched" || report.RootRunning || report.Descendants != 1 || report.DescendantsRunning != 0 {
		t.Fatalf("force stop must end the root and its child: %+v", report)
	}
	if running(leaf) {
		t.Fatal("the descendant is still running")
	}
	if report := dispatchExactTree(root.Process.Pid, startedAt, false, time.Second); report.Outcome != "exited" && report.Outcome != "stale" {
		t.Fatalf("a stopped lifetime must be reported as gone: %+v", report)
	}
}

// A timed-out command is stopped as the caller's own child. A process that is
// not a direct child of the caller (here, the leaf) must never be accepted.
func TestOwnChildTreeAcceptsOnlyDirectChildren(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := exec.Command(self, "-test.run=^TestExactWindowsTreeStopsOnlyItsOwnDescendants$")
	root.Env = append(os.Environ(), treeStage+"=root")
	stdout, err := root.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Process.Kill(); _ = root.Wait() })
	scanner := bufio.NewScanner(stdout)
	leafPID := 0
	for scanner.Scan() {
		if value, found := strings.CutPrefix(scanner.Text(), "LEAF "); found {
			leafPID, _ = strconv.Atoi(value)
			break
		}
	}
	leaf, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(leafPID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(leaf) }()
	t.Cleanup(func() { _ = windows.TerminateProcess(leaf, 1) })

	if report := dispatchOwnChildTree(leafPID, os.Getpid(), time.Second); report.Outcome != "stale" || !running(leaf) {
		t.Fatalf("a grandchild is not the caller's own child: %+v", report)
	}
	report := dispatchOwnChildTree(root.Process.Pid, os.Getpid(), 5*time.Second)
	if report.Outcome != "dispatched" || report.RootRunning || report.Descendants != 1 || report.DescendantsRunning != 0 || running(leaf) {
		t.Fatalf("the caller's child and its descendant must stop: %+v", report)
	}
}
