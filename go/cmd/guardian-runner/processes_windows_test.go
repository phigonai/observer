//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
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
