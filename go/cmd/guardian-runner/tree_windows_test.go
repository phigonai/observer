//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
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
		// Without a terminal, so Windows starts no console host beside it.
		leaf.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
		if err := leaf.Start(); err != nil {
			os.Exit(3)
		}
		fmt.Printf("LEAF %d\n", leaf.Process.Pid)
		time.Sleep(time.Minute)
		return
	}

	root := exec.Command(self, "-test.run=^TestExactWindowsTreeStopsOnlyItsOwnDescendants$")
	root.Env = append(os.Environ(), treeStage+"=root")
	// No window and no terminal: nothing a graceful stop could ask.
	root.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
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
	// A process with neither a window nor a terminal: nothing may be sent.
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

const consoleStage = "PHIGON_TEST_CONSOLE_STAGE"
const consoleHost = "PHIGON_TEST_CONSOLE_HOST"

// startConsoleAgent starts a copy of this test binary in its own hidden
// terminal that exits cleanly on Ctrl+C, like a terminal agent.
func startConsoleAgent(t *testing.T, test string) (*exec.Cmd, time.Time) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	agent := exec.Command(self, "-test.run=^"+test+"$")
	agent.Env = append(os.Environ(), consoleStage+"=agent")
	agent.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE, HideWindow: true}
	stdout, err := agent.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Process.Kill(); _ = agent.Wait() })
	waitForLine(t, stdout, "READY")
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(agent.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	created, err := creationTime(handle)
	_ = windows.CloseHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	return agent, time.Unix(0, created)
}

func waitForLine(t *testing.T, from interface{ Read([]byte) (int, error) }, line string) {
	t.Helper()
	scanner := bufio.NewScanner(from)
	for scanner.Scan() {
		if scanner.Text() == line {
			return
		}
	}
	t.Fatalf("the test process never printed %s", line)
}

// runConsoleStage plays a terminal agent (exit 0 on Ctrl+C) or a stranger
// that attaches itself to that agent's terminal.
func runConsoleStage() {
	switch os.Getenv(consoleStage) {
	case "agent":
		// Like a program started from a terminal: Ctrl+C is not ignored, even
		// if the process that ran the tests passed that setting down.
		_, _, _ = procSetConsoleCtrlHandler.Call(0, 0)
		interrupted := make(chan os.Signal, 1)
		signal.Notify(interrupted, os.Interrupt)
		fmt.Println("READY")
		select {
		case <-interrupted:
			os.Exit(0)
		case <-time.After(time.Minute):
			os.Exit(4)
		}
	case "guest":
		host, _ := strconv.Atoi(os.Getenv(consoleHost))
		_, _, _ = procFreeConsole.Call()
		if attached, _, _ := procAttachConsole.Call(uintptr(host)); attached == 0 {
			os.Exit(5)
		}
		fmt.Println("ATTACHED")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestGracefulStopPressesCtrlCInATerminalAgentsOwnTerminal(t *testing.T) {
	runConsoleStage()
	agent, startedAt := startConsoleAgent(t, "TestGracefulStopPressesCtrlCInATerminalAgentsOwnTerminal")
	report := dispatchExactTree(agent.Process.Pid, startedAt, true, 5*time.Second)
	if report.Outcome != "dispatched" || report.RootRunning {
		t.Fatalf("a terminal agent alone in its terminal must stop on Ctrl+C: %+v", report)
	}
	if err := agent.Wait(); err != nil {
		t.Fatalf("the agent did not exit through its Ctrl+C handler: %v", err)
	}
}

func TestGracefulStopSendsNothingWhenAnotherProgramSharesTheTerminal(t *testing.T) {
	runConsoleStage()
	agent, startedAt := startConsoleAgent(t, "TestGracefulStopSendsNothingWhenAnotherProgramSharesTheTerminal")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	guest := exec.Command(self, "-test.run=^TestGracefulStopSendsNothingWhenAnotherProgramSharesTheTerminal$")
	guest.Env = append(os.Environ(), consoleStage+"=guest", fmt.Sprintf("%s=%d", consoleHost, agent.Process.Pid))
	guest.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	stdout, err := guest.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := guest.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guest.Process.Kill(); _ = guest.Wait() })
	waitForLine(t, stdout, "ATTACHED")

	report := dispatchExactTree(agent.Process.Pid, startedAt, true, time.Second)
	if report.Outcome != "console_shared" || !report.RootRunning {
		t.Fatalf("Ctrl+C must not be sent to a terminal another program shares: %+v", report)
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(agent.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if !running(handle) {
		t.Fatal("the agent stopped although nothing was to be sent")
	}
}
