package main

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestDescendantsFollowEveryBranchButNoOtherProcess(t *testing.T) {
	table := []processRecord{
		{PID: 1, PPID: 0}, {PID: 10, PPID: 1}, // the runner
		{PID: 11, PPID: 10}, {PID: 12, PPID: 11}, {PID: 13, PPID: 12, Exited: true},
		{PID: 14, PPID: 10},                     // an orphan adopted by the subreaper
		{PID: 20, PPID: 1}, {PID: 21, PPID: 20}, // unrelated
	}
	var pids []int
	for _, record := range descendantsOf(10, table) {
		pids = append(pids, record.PID)
	}
	slices.Sort(pids)
	if !slices.Equal(pids, []int{11, 12, 13, 14}) {
		t.Fatalf("descendants = %v", pids)
	}
}

// On macOS an orphan moves to launchd. A descendant seen during the run is
// still a target later, but only while the same process lifetime runs.
func TestRememberedDescendantsKeepTheirLifetime(t *testing.T) {
	tracker := newDescendantTracker(10)
	tracker.observe([]processRecord{{PID: 10, PPID: 1}, {PID: 11, PPID: 10, Start: 5}, {PID: 12, PPID: 11, Start: 6}})
	// 11 exited; 12 now belongs to launchd; 13 reused nothing of ours.
	later := []processRecord{{PID: 10, PPID: 1}, {PID: 12, PPID: 1, Start: 6}, {PID: 13, PPID: 1, Start: 7}}
	targets := tracker.targets(later)
	if len(targets) != 1 || targets[0].PID != 12 {
		t.Fatalf("targets = %+v", targets)
	}
	// PID 12 reused by another program: never a target.
	reused := []processRecord{{PID: 10, PPID: 1}, {PID: 12, PPID: 1, Start: 99}}
	if targets := tracker.targets(reused); len(targets) != 0 {
		t.Fatalf("a reused PID became a target: %+v", targets)
	}
}

// A child that detaches with setsid leads a new process group, and its own
// children join that group. While every snapshot shows the group occupied,
// its members are targets even if they were never seen and now belong to
// launchd. Once a snapshot shows it empty, its number may be reused for an
// unrelated group, so it is forgotten.
func TestGroupMembersAreTargetsWhileTheGroupStaysOccupied(t *testing.T) {
	pids := func(records []processRecord) []int {
		var result []int
		for _, record := range records {
			result = append(result, record.PID)
		}
		slices.Sort(result)
		return result
	}
	first := []processRecord{
		{PID: 10, PPID: 1, PGID: 5},
		{PID: 11, PPID: 10, PGID: 11, Start: 3},
		{PID: 12, PPID: 11, PGID: 12, Start: 4}, // detached: leads group 12
	}

	// The leader forks a child and exits before the next snapshot.
	tracker := newDescendantTracker(10)
	tracker.observe(first)
	detached := []processRecord{
		{PID: 10, PPID: 1, PGID: 5},
		{PID: 30, PPID: 1, PGID: 12, Start: 9}, // never seen, now under launchd
		{PID: 31, PPID: 1, PGID: 31, Start: 9}, // unrelated
		{PID: 32, PPID: 1, PGID: 5, Start: 9},  // shares the runner's own group
	}
	if got := pids(tracker.targets(detached)); !slices.Equal(got, []int{30}) {
		t.Fatalf("detached child of an exited leader: targets = %v", got)
	}

	// The group empties in one snapshot and its number is reused later.
	tracker = newDescendantTracker(10)
	tracker.observe(first)
	tracker.observe([]processRecord{{PID: 10, PPID: 1, PGID: 5}})
	reused := []processRecord{
		{PID: 10, PPID: 1, PGID: 5},
		{PID: 12, PPID: 1, PGID: 12, Start: 50}, // another program's group leader
		{PID: 40, PPID: 12, PGID: 12, Start: 51},
	}
	if got := tracker.targets(reused); len(got) != 0 {
		t.Fatalf("members of a reused group number became targets: %+v", got)
	}
}

// fakeTracker runs the sweep against a process table held in memory.
func fakeTracker(table *[]processRecord, listErr error, killable bool) *descendantTracker {
	tracker := newDescendantTracker(10)
	tracker.list = func() ([]processRecord, error) { return append([]processRecord(nil), *table...), listErr }
	tracker.reap = func([]processRecord, int) {}
	tracker.kill = func(target processRecord) {
		if !killable {
			return
		}
		kept := (*table)[:0]
		for _, record := range *table {
			if record.PID != target.PID {
				kept = append(kept, record)
			}
		}
		*table = kept
	}
	return tracker
}

// A run whose cleanup cannot confirm that every descendant stopped must fail,
// whatever the command itself returned.
func TestUnconfirmedCleanupFailsTheRun(t *testing.T) {
	previous, wait := contained, sweepWait
	t.Cleanup(func() { contained, sweepWait = previous, wait })
	sweepWait = 50 * time.Millisecond
	tree := func() []processRecord {
		return []processRecord{{PID: 10, PPID: 1, PGID: 5}, {PID: 11, PPID: 10, PGID: 11, Start: 3}, {PID: 12, PPID: 11, PGID: 11, Start: 4}}
	}

	table := tree()
	contained = fakeTracker(&table, nil, true)
	if !sweepDescendants(11) || len(table) != 1 {
		t.Fatalf("descendants that stop must confirm cleanup; left %+v", table)
	}
	table = tree()
	contained = fakeTracker(&table, nil, false)
	if sweepDescendants(11) {
		t.Fatal("a descendant that keeps running was reported as stopped")
	}
	table = tree()
	contained = fakeTracker(&table, errors.New("process table unavailable"), true)
	if sweepDescendants(11) {
		t.Fatal("an unreadable process table was reported as a confirmed cleanup")
	}

	if code := finishedExitCode(nil, false); code != 77 {
		t.Fatalf("a successful command with unconfirmed cleanup returned %d", code)
	}
	if code := finishedExitCode(nil, true); code != 0 {
		t.Fatalf("a successful command with confirmed cleanup returned %d", code)
	}
}
