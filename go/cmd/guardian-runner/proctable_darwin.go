//go:build darwin

package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const darwinZombie = 5 // SZOMB in <sys/proc.h>

func darwinRecord(process *unix.KinfoProc) processRecord {
	started := process.Proc.P_starttime
	return processRecord{
		PID:    int(process.Proc.P_pid),
		PPID:   int(process.Eproc.Ppid),
		PGID:   int(process.Eproc.Pgid),
		Start:  uint64(started.Sec)*1_000_000 + uint64(started.Usec), // #nosec G115 -- Kernel start times are non-negative.
		Exited: process.Proc.P_stat == darwinZombie,
	}
}

func listProcessTable() ([]processRecord, error) {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	table := make([]processRecord, 0, len(processes))
	for index := range processes {
		table = append(table, darwinRecord(&processes[index]))
	}
	return table, nil
}

// killProcess sends SIGKILL only if the PID still names the recorded process
// lifetime. macOS has no pidfd, so a PID reused in the instant between the
// check and the signal is the remaining, unavoidable race.
func killProcess(target processRecord) {
	process, err := unix.SysctlKinfoProc("kern.proc.pid", target.PID)
	if err != nil || process == nil || process.Proc.P_pid != int32(target.PID) { // #nosec G115 -- PIDs fit in 32 bits.
		return
	}
	if current := darwinRecord(process); current.Start == target.Start && !current.Exited {
		_ = unix.Kill(target.PID, unix.SIGKILL)
	}
}

// macOS has no child subreaper: orphans move to launchd, which reaps them.
func reapAdopted(_ []processRecord, _ int) {}

func trackDescendants() error {
	tracker := newDescendantTracker(os.Getpid())
	tracker.list, tracker.kill, tracker.reap = listProcessTable, killProcess, reapAdopted
	contained = tracker
	return nil
}

// macOS has no subreaper and no unprivileged way to follow forks (kqueue's
// NOTE_TRACK is unsupported), so the tree is snapshotted five times a second:
// a descendant seen once is still known, with the process group it leads,
// after it detaches to launchd. One sysctl per snapshot bounds the cost.
func containmentInterval() time.Duration { return 200 * time.Millisecond }

func observeContained(_ int) {
	if contained == nil {
		return
	}
	if table, err := listProcessTable(); err == nil {
		contained.observe(table)
	}
}
