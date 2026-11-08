package main

import (
	"sync"
	"time"
)

// processRecord is one row of a process-table snapshot. Start is the kernel's
// start time for the process; with PID it names one process lifetime.
type processRecord struct {
	PID    int
	PPID   int
	PGID   int
	Start  uint64
	Exited bool // a zombie: already dead, only waiting to be reaped
}

// descendantsOf returns every process below root in table, root excluded.
func descendantsOf(root int, table []processRecord) []processRecord {
	children := map[int][]processRecord{}
	for _, record := range table {
		if record.PID != record.PPID {
			children[record.PPID] = append(children[record.PPID], record)
		}
	}
	var result []processRecord
	seen := map[int]bool{root: true}
	for queue := []int{root}; len(queue) > 0; queue = queue[1:] {
		for _, child := range children[queue[0]] {
			if !seen[child.PID] {
				seen[child.PID] = true
				result = append(result, child)
				queue = append(queue, child.PID)
			}
		}
	}
	return result
}

// descendantTracker finds every process a managed command started, including
// ones that left its process group with setsid or a double fork. On Linux the
// runner is a child subreaper, so orphans stay below it. On macOS an orphan
// moves to launchd, so descendants seen while running are remembered, with
// the process groups they lead: setsid also starts a new group, which the
// detached process's children join.
//
// A group ID is a number the kernel never hands out as a new PID while any
// process is still in that group. A remembered group therefore stays valid as
// long as every snapshot shows at least one process in it, and its current
// members are adopted as targets. It is forgotten the first time a snapshot
// shows it empty; only a group that empties and is recreated under the same
// number within a single snapshot interval could be mistaken for it.
type descendantTracker struct {
	root   int
	mu     sync.Mutex
	seen   map[int]processRecord
	groups map[int]bool // groups led by a descendant when first seen

	// Platform operations, set by trackDescendants.
	list func() ([]processRecord, error)
	kill func(processRecord)
	reap func(table []processRecord, main int)
}

func newDescendantTracker(root int) *descendantTracker {
	return &descendantTracker{root: root, seen: map[int]processRecord{}, groups: map[int]bool{}}
}

// observe records the live descendants in table, the groups they lead and the
// members of those groups, and forgets processes that ended and groups that
// are empty, so memory stays bounded by the live process tree.
func (t *descendantTracker) observe(table []processRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, record := range descendantsOf(t.root, table) {
		if record.Exited {
			continue
		}
		t.seen[record.PID] = record
		if record.PGID == record.PID {
			t.groups[record.PID] = true
		}
	}
	running := make(map[int]uint64, len(table))
	for _, record := range table {
		if !record.Exited {
			running[record.PID] = record.Start
		}
	}
	for pid, record := range t.seen {
		if start, ok := running[pid]; !ok || start != record.Start {
			delete(t.seen, pid)
		}
	}
	// An empty group's number may be reused for an unrelated group.
	occupied := map[int]bool{}
	for _, record := range table {
		if !record.Exited {
			occupied[record.PGID] = true
		}
	}
	for group := range t.groups {
		if !occupied[group] {
			delete(t.groups, group)
		}
	}
	for _, record := range table {
		if !record.Exited && record.PID != t.root && t.groups[record.PGID] {
			t.seen[record.PID] = record
		}
	}
}

// targets lists every remembered process still running with the same start
// time after observing table.
func (t *descendantTracker) targets(table []processRecord) []processRecord {
	t.observe(table)
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]processRecord, 0, len(t.seen))
	for _, record := range t.seen {
		result = append(result, record)
	}
	return result
}

// sweep kills every descendant until none is left or wait passes, and returns
// how many were still running at the deadline (-1 if the table was unreadable).
// main is the managed command itself, which only its exec.Cmd may reap.
func (t *descendantTracker) sweep(main int, wait time.Duration) int {
	deadline := time.Now().Add(wait)
	for {
		table, err := t.list()
		if err != nil {
			return -1
		}
		t.reap(table, main)
		targets := t.targets(table)
		if len(targets) == 0 {
			return 0
		}
		// A process killed while forking does not complete the fork, and a
		// child created just before is found on the next pass.
		for _, target := range targets {
			t.kill(target)
		}
		if time.Now().After(deadline) {
			return len(targets)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// contained tracks the managed command's descendants once containment is set up.
var contained *descendantTracker

// sweepWait bounds how long the end of a run waits for descendants to stop.
var sweepWait = 2 * time.Second

// sweepDescendants stops everything the managed command started and reports
// whether it could confirm that nothing is left running.
func sweepDescendants(main int) bool {
	return contained == nil || contained.sweep(main, sweepWait) == 0
}
