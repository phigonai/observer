//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestProcessListingDescribesThisProcess(t *testing.T) {
	var output bytes.Buffer
	if code := listProcesses(&output); code != 0 {
		t.Fatalf("listing exited with %d", code)
	}
	var entries []processEntry
	if err := json.Unmarshal(output.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	var self *processEntry
	for index := range entries {
		if entries[index].PID == uint32(os.Getpid()) {
			self = &entries[index]
		}
	}
	if self == nil {
		t.Fatalf("this process is missing from %d entries", len(entries))
	}
	if self.ParentPID != uint32(os.Getppid()) {
		t.Fatalf("parent %d, want %d", self.ParentPID, os.Getppid())
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	if want := created.Nanoseconds() / 1_000_000; self.CreatedMs != want {
		t.Fatalf("created %d, want %d", self.CreatedMs, want)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(self.Path, executable) || !strings.EqualFold(self.Name, executable[strings.LastIndex(executable, `\`)+1:]) {
		t.Fatalf("path or name does not describe %s", executable)
	}
}

func TestCommandLineOfThisProcessIsRead(t *testing.T) {
	process, err := windows.OpenProcess(imagePathAccess, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	// A small first buffer exercises the retry with the size Windows asks for.
	commandLine := processCommandLine(process, make([]byte, 32))
	if got := windowsArguments(commandLine); !reflect.DeepEqual(got, os.Args) {
		t.Fatalf("command line splits into %d arguments, want %d", len(got), len(os.Args))
	}
}

func TestListingReportsOnlyThePackageANodeProcessRuns(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is not installed")
	}
	directory := t.TempDir()
	agent := filepath.Join(directory, "Dev User", "node_modules", "@phigon-test", "agent", "cli.js")
	plain := filepath.Join(directory, "Dev User", "project", "server.js")
	for _, script := range []string{agent, plain} {
		if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(script, []byte("setInterval(() => {}, 1000);\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	marker := "--phigon-marker-" + strings.Repeat("7", 12)
	start := func(script string) int {
		command := exec.Command(node, script, marker) // #nosec G204 -- test starts Node.js with its own script.
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		// Registered after TempDir, so it runs first and releases the files.
		t.Cleanup(func() {
			_ = command.Process.Kill()
			_ = command.Wait()
		})
		return command.Process.Pid
	}
	agentPID, plainPID := start(agent), start(plain)

	var output bytes.Buffer
	if code := listProcesses(&output); code != 0 {
		t.Fatalf("listing exited with %d", code)
	}
	if strings.Contains(output.String(), marker) || strings.Contains(output.String(), "Dev User") {
		t.Fatal("the listing contains command-line text")
	}
	var entries []processEntry
	if err := json.Unmarshal(output.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	scripts := map[int]string{}
	for _, entry := range entries {
		if entry.PID == uint32(agentPID) || entry.PID == uint32(plainPID) || entry.PID == uint32(os.Getpid()) {
			scripts[int(entry.PID)] = entry.Script
		}
	}
	if len(scripts) != 3 {
		t.Fatalf("found %d of 3 processes", len(scripts))
	}
	if scripts[agentPID] != "@phigon-test/agent" || scripts[plainPID] != "" || scripts[os.Getpid()] != "" {
		t.Fatalf("scripts = %v", scripts)
	}
}

func TestSnapshotStringRejectsAddressesOutsideTheBuffer(t *testing.T) {
	buffer := make([]byte, 16)
	outside := make([]uint16, 4)
	if _, ok := snapshotString(buffer, windows.NTUnicodeString{Length: 8, Buffer: &outside[0]}); ok {
		t.Fatal("a string outside the snapshot was accepted")
	}
	inside := (*uint16)(unsafe.Pointer(&buffer[12]))
	if _, ok := snapshotString(buffer, windows.NTUnicodeString{Length: 8, Buffer: inside}); ok {
		t.Fatal("a string running past the snapshot was accepted")
	}
	copy(buffer[8:], []byte{'o', 0, 'k', 0})
	if value, ok := snapshotString(buffer, windows.NTUnicodeString{Length: 4, Buffer: (*uint16)(unsafe.Pointer(&buffer[8]))}); !ok || value != "ok" {
		t.Fatalf("got %q, %v", value, ok)
	}
}
