//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// listProcessTable reads every process from procfs. Processes that end while
// it reads are simply missing from the snapshot.
func listProcessTable() ([]processRecord, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	table := make([]processRecord, 0, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if record, ok := readProcessRecord(pid); ok {
			table = append(table, record)
		}
	}
	return table, nil
}

func readProcessRecord(pid int) (processRecord, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat") // #nosec G304 -- Fixed procfs path built from a decimal PID.
	if err != nil {
		return processRecord{}, false
	}
	return parseProcessStat(pid, data)
}

// parseProcessStat reads state, parent and start time from /proc/<pid>/stat.
// The command name may contain spaces and parentheses, so fields are counted
// from its last closing parenthesis.
func parseProcessStat(pid int, data []byte) (processRecord, bool) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+2 > len(data) {
		return processRecord{}, false
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) < 20 {
		return processRecord{}, false
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return processRecord{}, false
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return processRecord{}, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processRecord{}, false
	}
	return processRecord{PID: pid, PPID: parent, PGID: group, Start: start, Exited: fields[0] == "Z" || fields[0] == "X"}, true
}

// killProcess sends SIGKILL to exactly the recorded process lifetime. A pidfd
// pins the process, so a reused PID is never signalled.
func killProcess(target processRecord) {
	fd, err := unix.PidfdOpen(target.PID, 0)
	if err == nil {
		defer unix.Close(fd)
	}
	current, ok := readProcessRecord(target.PID)
	if !ok || current.Start != target.Start || current.Exited {
		return
	}
	if err == nil {
		_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		return
	}
	// Kernels before 5.3 have no pidfd; the start-time check above leaves only
	// the instant between it and this call for the PID to be reused.
	_ = unix.Kill(target.PID, unix.SIGKILL)
}

// reapAdopted collects the exit status of orphans the subreaper adopted, so
// they do not pile up as zombies. The managed command is left to exec.Cmd.
func reapAdopted(table []processRecord, main int) {
	self := os.Getpid()
	for _, record := range table {
		if record.PPID == self && record.Exited && record.PID != main {
			var status unix.WaitStatus
			_, _ = unix.Wait4(record.PID, &status, unix.WNOHANG, nil)
		}
	}
}

// trackDescendants makes this runner a child subreaper: every orphaned
// descendant stays below it instead of moving to init, so a double fork or
// setsid cannot hide a process from cleanup.
func trackDescendants() error {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("could not keep the agent's processes under Guardian: %w", err)
	}
	tracker := newDescendantTracker(os.Getpid())
	tracker.list, tracker.kill, tracker.reap = listProcessTable, killProcess, reapAdopted
	contained = tracker
	return nil
}

// With the subreaper the tree needs no tracking while the command runs;
// observeContained only reaps adopted zombies now and then.
func containmentInterval() time.Duration { return 10 * time.Second }

func observeContained(main int) {
	if contained == nil {
		return
	}
	if table, err := listProcessTable(); err == nil {
		reapAdopted(table, main)
	}
}
