//go:build linux

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The reviewed path is replaced after its hash was checked. The command must
// still run the hashed program, never the replacement.
func TestReplacedExecutableAfterHashIsNotRun(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "agent")
	source, err := os.Open("/bin/true")
	if err != nil {
		t.Skip("this system has no /bin/true")
	}
	copyFile(t, source, target)
	file, err := openExecutionFile(target)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	pinned := pinnedExecutablePath(file)
	if !strings.HasPrefix(pinned, "/proc/self/fd/") {
		t.Fatalf("an ELF executable should be pinned, got %q", pinned)
	}
	marker := filepath.Join(directory, "swapped")
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\necho swapped > '"+marker+"'\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, target); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(target)
	command.Path = pinned
	if err := command.Run(); err != nil {
		t.Fatalf("the hashed program did not run: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the replacement ran instead of the hashed program")
	}
}

// Scripts are read again by their interpreter, so they keep running by path.
func TestScriptsAreNotPinned(t *testing.T) {
	script := filepath.Join(t.TempDir(), "agent.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := openExecutionFile(script)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if pinned := pinnedExecutablePath(file); pinned != "" {
		t.Fatalf("a script was pinned to %q", pinned)
	}
}

func copyFile(t *testing.T, source *os.File, target string) {
	t.Helper()
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
}
