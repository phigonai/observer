//go:build windows

package main

import (
	"errors"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole         = kernel32.NewProc("AttachConsole")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procSetConsoleCtrlHandler = kernel32.NewProc("SetConsoleCtrlHandler")
	// Answers Ctrl+C for this helper while it is attached to an agent's
	// terminal, so the press meant for the agent never ends the helper.
	ignoreCtrlC = windows.NewCallback(func(uint32) uintptr { return 1 })
)

// attachParentProcess is ATTACH_PARENT_PROCESS ((DWORD)-1).
const attachParentProcess = ^uintptr(0) & 0xFFFFFFFF

// consoleShells may share a terminal with the agent they started: a shell
// does not exit on Ctrl+C, it returns to its prompt.
var consoleShells = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "bash.exe": true,
	"sh.exe": true, "zsh.exe": true, "fish.exe": true, "nu.exe": true,
}

// interruptConsole stops a terminal agent the way a person would: by pressing
// Ctrl+C in its terminal, and once more if it is still running (Claude Code and
// Gemini CLI ask for a second press). Ctrl+C reaches everything attached to
// that terminal, so it is sent only when every attached process is the agent,
// one of its verified descendants, or a shell directly above it. It returns ""
// once sent, or the outcome to report when nothing was sent.
func interruptConsole(members []treeMember, rootRunning func() bool) string {
	parents, names, err := processTable()
	if err != nil {
		return "failed"
	}
	allowed := map[uint32]bool{uint32(os.Getpid()): true}
	for _, member := range members {
		allowed[member.pid] = true
	}
	for pid := parents[members[0].pid]; pid != 0 && !allowed[pid]; pid = parents[pid] {
		if !consoleShells[strings.ToLower(names[pid])] {
			break
		}
		allowed[pid] = true
	}

	// The observer starts this helper without a terminal. A caller that has
	// one leaves it to attach to the agent's, and gets its parent's back after.
	probe := make([]uint32, 1)
	hadConsole, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&probe[0])), 1) // #nosec G103 -- Win32 ABI takes the buffer address.
	_, _, _ = procFreeConsole.Call()
	defer func() {
		if hadConsole != 0 {
			_, _, _ = procAttachConsole.Call(attachParentProcess)
		}
	}()
	if attached, _, _ := procAttachConsole.Call(uintptr(members[0].pid)); attached == 0 {
		return "graceful_unsupported"
	}
	defer func() { _, _, _ = procFreeConsole.Call() }()
	clients := make([]uint32, 256)
	count, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&clients[0])), uintptr(len(clients))) // #nosec G103 -- Win32 ABI takes the buffer address.
	if count == 0 || int(count) > len(clients) {
		return "console_shared"
	}
	for _, pid := range clients[:count] {
		if !allowed[pid] {
			return "console_shared"
		}
	}
	_, _, _ = procSetConsoleCtrlHandler.Call(ignoreCtrlC, 1)
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0); err != nil {
		return "failed"
	}
	time.Sleep(700 * time.Millisecond)
	if rootRunning() {
		_ = windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0)
	}
	return ""
}

// processTable maps every process to its parent and executable name.
func processTable() (map[uint32]uint32, map[uint32]string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	parents := map[uint32]uint32{}
	names := map[uint32]string{}
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry)) // #nosec G103 -- Win32 ABI requires the exact structure size.
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID != entry.ParentProcessID {
			parents[entry.ProcessID] = entry.ParentProcessID
		}
		names[entry.ProcessID] = windows.UTF16ToString(entry.ExeFile[:])
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, nil, err
	}
	return parents, names, nil
}
