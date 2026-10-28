//go:build windows

package main

import (
	"errors"
	"math"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	treeAccess = windows.PROCESS_TERMINATE | windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE
	wmClose    = 0x0010
)

var postMessage = windows.NewLazySystemDLL("user32.dll").NewProc("PostMessageW")

type treeMember struct {
	pid     uint32
	handle  windows.Handle
	created int64
}

// dispatchExactTree stops one exact process lifetime and its descendants.
// Every member is opened and verified before anything is sent, and its
// handle stays open until the report is written, so Windows cannot recycle
// a member's PID to an unrelated process during the operation. A child is
// accepted only when it was created after its verified parent, which rejects
// stale parent PIDs left behind by exited processes.
func dispatchExactTree(pid int, expected time.Time, graceful bool, wait time.Duration) treeReport {
	return dispatchTree(pid, graceful, wait,
		func(created int64) bool { return created/int64(time.Millisecond) == expected.UnixMilli() },
		func(err error) treeReport { return openFailure(uint32(pid), expected, err) })
}

// dispatchOwnChildTree force-stops a process the caller started itself, such
// as a timed-out remote command, and its verified descendants. The PID is
// trusted only as a direct child of callerPID created after the caller.
// Unlike taskkill /T, no process whose recorded parent PID was merely reused
// is included.
func dispatchOwnChildTree(pid int, callerPID int, wait time.Duration) treeReport {
	return dispatchTree(pid, false, wait,
		func(created int64) bool { return isChildOf(uint32(pid), created, uint32(callerPID)) },
		func(err error) treeReport {
			switch {
			case errors.Is(err, windows.ERROR_INVALID_PARAMETER):
				return treeReport{Outcome: "exited"}
			case errors.Is(err, windows.ERROR_ACCESS_DENIED):
				return treeReport{Outcome: "access_denied", RootRunning: true}
			default:
				return treeReport{Outcome: "failed", Error: err.Error()}
			}
		})
}

func dispatchTree(pid int, graceful bool, wait time.Duration, verified func(created int64) bool, openFailed func(error) treeReport) treeReport {
	if pid <= 4 || int64(pid) > math.MaxUint32 {
		return treeReport{Outcome: "invalid"}
	}
	rootHandle, err := windows.OpenProcess(treeAccess, false, uint32(pid))
	if err != nil {
		return openFailed(err)
	}
	members := []treeMember{{pid: uint32(pid), handle: rootHandle}}
	defer func() {
		for _, member := range members {
			_ = windows.CloseHandle(member.handle)
		}
	}()
	created, err := creationTime(rootHandle)
	if err != nil {
		return treeReport{Outcome: "failed", Error: err.Error()}
	}
	if !verified(created) {
		return treeReport{Outcome: "stale"}
	}
	if !running(rootHandle) {
		return treeReport{Outcome: "exited"}
	}
	members[0].created = created
	seen := map[uint32]bool{uint32(pid): true}
	// The observer and this helper are never members, nor is anything they started.
	excluded := map[uint32]bool{uint32(os.Getpid()): true, uint32(os.Getppid()): true}
	report := treeReport{Outcome: "dispatched"}
	denied, scanErr := collectDescendants(&members, seen, excluded)
	report.DescendantsDenied += denied
	if scanErr != nil {
		report.Error = "descendant scan failed"
	}

	if graceful {
		windowsByOwner := topLevelWindows(members)
		if len(windowsByOwner[members[0].pid]) == 0 {
			// Windows can only ask a process to exit by closing its windows.
			// Console agents have none; never escalate to force silently.
			return treeReport{Outcome: "graceful_unsupported", RootRunning: true, Descendants: len(members) - 1}
		}
		for _, member := range members {
			for _, window := range windowsByOwner[member.pid] {
				_, _, _ = postMessage.Call(uintptr(window), wmClose, 0, 0)
			}
		}
	} else {
		terminated := 0
		// Rescan after each pass: a member may have started a child after the
		// first snapshot. Held handles keep the parent-child check exact.
		for pass := 0; pass < 3 && terminated < len(members); pass++ {
			for _, member := range members[terminated:] {
				if running(member.handle) {
					_ = windows.TerminateProcess(member.handle, 1)
				}
			}
			terminated = len(members)
			denied, err := collectDescendants(&members, seen, excluded)
			report.DescendantsDenied += denied
			if err != nil {
				report.Error = "descendant scan failed"
			}
		}
	}

	deadline := time.Now().Add(wait)
	for _, member := range members {
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
		_, _ = windows.WaitForSingleObject(member.handle, uint32(remaining.Milliseconds()))
	}
	report.RootRunning = running(members[0].handle)
	report.Descendants = len(members) - 1
	for _, member := range members[1:] {
		if running(member.handle) {
			report.DescendantsRunning++
		}
	}
	return report
}

func openFailure(pid uint32, expected time.Time, err error) treeReport {
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return treeReport{Outcome: "exited"}
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return treeReport{Outcome: "failed", Error: err.Error()}
	}
	// Distinguish "this exact process is protected" from "the PID was reused
	// by a protected process" whenever the limited query right is available.
	handle, queryErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if queryErr != nil {
		return treeReport{Outcome: "access_denied", RootRunning: true}
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	created, timeErr := creationTime(handle)
	if timeErr == nil && created/int64(time.Millisecond) != expected.UnixMilli() {
		return treeReport{Outcome: "stale"}
	}
	return treeReport{Outcome: "access_denied", RootRunning: true}
}

func collectDescendants(members *[]treeMember, seen map[uint32]bool, excluded map[uint32]bool) (int, error) {
	children, err := childrenByParent()
	if err != nil {
		return 0, err
	}
	denied := 0
	for index := 0; index < len(*members); index++ {
		parent := (*members)[index]
		for _, child := range children[parent.pid] {
			if seen[child] || excluded[child] || child <= 4 || len(*members) > maxTreeMembers {
				continue
			}
			seen[child] = true
			handle, err := windows.OpenProcess(treeAccess, false, child)
			if err != nil {
				if errors.Is(err, windows.ERROR_ACCESS_DENIED) && createdAfter(child, parent.created) {
					denied++
				}
				continue
			}
			created, err := creationTime(handle)
			if err != nil || created < parent.created || !running(handle) {
				_ = windows.CloseHandle(handle)
				continue
			}
			*members = append(*members, treeMember{pid: child, handle: handle, created: created})
		}
	}
	return denied, nil
}

func isChildOf(pid uint32, created int64, caller uint32) bool {
	children, err := childrenByParent()
	if err != nil {
		return false
	}
	isChild := false
	for _, child := range children[caller] {
		isChild = isChild || child == pid
	}
	if !isChild {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, caller)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	callerCreated, err := creationTime(handle)
	return err == nil && created >= callerCreated
}

func createdAfter(pid uint32, parentCreated int64) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	created, err := creationTime(handle)
	return err == nil && created >= parentCreated && running(handle)
}

func childrenByParent() (map[uint32][]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	children := map[uint32][]uint32{}
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry)) // #nosec G103 -- Win32 ABI requires the exact structure size.
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID != entry.ParentProcessID {
			children[entry.ParentProcessID] = append(children[entry.ParentProcessID], entry.ProcessID)
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return children, nil
}

func topLevelWindows(members []treeMember) map[uint32][]windows.HWND {
	owners := map[uint32]bool{}
	for _, member := range members {
		owners[member.pid] = true
	}
	found := map[uint32][]windows.HWND{}
	callback := windows.NewCallback(func(window windows.HWND, _ uintptr) uintptr {
		var owner uint32
		if _, err := windows.GetWindowThreadProcessId(window, &owner); err == nil && owners[owner] {
			found[owner] = append(found[owner], window)
		}
		return 1
	})
	_ = windows.EnumWindows(callback, nil)
	return found
}

func creationTime(handle windows.Handle) (int64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return created.Nanoseconds(), nil
}

func running(handle windows.Handle) bool {
	state, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && state == uint32(windows.WAIT_TIMEOUT)
}
