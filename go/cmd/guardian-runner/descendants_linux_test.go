//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProcessStatSurvivesUnusualCommandNames(t *testing.T) {
	stat := "4321 (a) (b) c) S 99 4321 4321 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 778899 0 0"
	record, ok := parseProcessStat(4321, []byte(stat))
	if !ok || record.PPID != 99 || record.PGID != 4321 || record.Start != 778899 || record.Exited {
		t.Fatalf("record=%+v ok=%v", record, ok)
	}
	zombie, ok := parseProcessStat(7, []byte("7 (gone) Z 1 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0"))
	if !ok || !zombie.Exited {
		t.Fatalf("zombie=%+v ok=%v", zombie, ok)
	}
	if _, ok := parseProcessStat(1, []byte("1 (truncated")); ok {
		t.Fatal("a truncated stat line must not parse")
	}
}

// A managed command that double-forks a setsid child and exits leaves no
// trace in its process group. The subreaper keeps the child below the runner,
// and the sweep that ends every run stops it.
func TestSweepStopsDetachedDescendants(t *testing.T) {
	if err := trackDescendants(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { contained = nil })
	marker := filepath.Join(t.TempDir(), "detached.pid")
	command := exec.Command("/bin/sh", "-c", `setsid /bin/sh -c 'sleep 60 & echo $! > "$1"; wait' detached "$1" &`, "agent", marker)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	var detached int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if data, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(data)) != "" {
			detached, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			break
		}
	}
	if detached == 0 || !running(detached) {
		t.Fatal("the detached test process did not start")
	}
	group, _ := syscall.Getpgid(detached)
	if group == command.Process.Pid {
		t.Fatal("the test process must have left the command's process group")
	}
	if !terminateContained(command, true) {
		t.Error("cleanup could not confirm that the detached descendant stopped")
	}
	for deadline := time.Now().Add(3 * time.Second); running(detached) && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	if running(detached) {
		_ = syscall.Kill(detached, syscall.SIGKILL)
		t.Fatal("a detached descendant survived the end of the run")
	}
}

func running(pid int) bool {
	record, ok := readProcessRecord(pid)
	return ok && !record.Exited
}
