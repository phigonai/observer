//go:build windows

package main

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// The Unix epoch in milliseconds since the FILETIME epoch (1601).
	fileTimeUnixEpochMs = 11_644_473_600_000
	// Bounds the snapshot buffer even if the process count keeps growing.
	maxProcessSnapshotBytes = 64 << 20
	// The only right the listing asks for. It never reads another
	// process's memory: opening processes (lsass among them) for memory
	// reads is what credential theft looks like to endpoint security tools.
	imagePathAccess = windows.PROCESS_QUERY_LIMITED_INFORMATION
)

var errProcessSnapshot = errors.New("process snapshot is malformed")

// processEntries lists every process from one kernel snapshot, which gives
// each process's ID, parent ID, creation time and image name without
// opening it. Only the image path needs the process to be opened.
func processEntries() ([]processEntry, error) {
	buffer, err := processSnapshot()
	if err != nil {
		return nil, err
	}
	entrySize := int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{}))
	path := make([]uint16, windows.MAX_LONG_PATH)
	entries := []processEntry{}
	for offset := 0; ; {
		if offset < 0 || offset > len(buffer)-entrySize {
			return nil, errProcessSnapshot
		}
		info := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset])) // #nosec G103 -- NtQuerySystemInformation writes these entries into this buffer.
		name, ok := snapshotString(buffer, info.ImageName)
		if !ok {
			return nil, errProcessSnapshot
		}
		entry := processEntry{
			PID:       uint32(info.UniqueProcessID),
			ParentPID: uint32(info.InheritedFromUniqueProcessID),
			Name:      name,
		}
		if entry.PID == 0 && name == "" {
			entry.Name = "System Idle Process" // Win32_Process's name for it.
		}
		if info.CreateTime > 0 {
			entry.CreatedMs = info.CreateTime/10_000 - fileTimeUnixEpochMs
		}
		if entry.PID != 0 {
			entry.Path = imagePath(entry.PID, path)
		}
		entries = append(entries, entry)
		if info.NextEntryOffset == 0 {
			return entries, nil
		}
		offset += int(info.NextEntryOffset)
	}
}

func processSnapshot() ([]byte, error) {
	size := uint32(512 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		buffer := make([]byte, size)
		var needed uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(&buffer[0]), size, &needed) // #nosec G103 -- Win32 ABI requires the buffer address and its exact size.
		if err == nil {
			return buffer, nil
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			return nil, err
		}
		// Processes can start between calls; leave room for them.
		next := uint64(needed) + 64<<10
		if next <= uint64(size) {
			next = uint64(size) * 2
		}
		if next > maxProcessSnapshotBytes {
			return nil, errProcessSnapshot
		}
		size = uint32(next)
	}
	return nil, errProcessSnapshot
}

// snapshotString decodes a string the kernel placed inside the snapshot
// buffer, rejecting one that points outside it.
func snapshotString(buffer []byte, value windows.NTUnicodeString) (string, bool) {
	if value.Length == 0 {
		return "", true
	}
	start := uintptr(unsafe.Pointer(value.Buffer)) - uintptr(unsafe.Pointer(&buffer[0])) // #nosec G103 -- Bounds check of a kernel-written pointer into this buffer.
	if value.Length%2 != 0 || start > uintptr(len(buffer)) || uintptr(value.Length) > uintptr(len(buffer))-start {
		return "", false
	}
	return windows.UTF16ToString(unsafe.Slice(value.Buffer, value.Length/2)), true // #nosec G103 -- Bounds checked above.
}

// imagePath returns the process's executable as a Win32 path, or "" when
// the process cannot be opened with limited query rights (as
// Win32_Process.ExecutablePath is null when access is denied). scratch is
// reused between calls.
func imagePath(pid uint32, scratch []uint16) string {
	process, err := windows.OpenProcess(imagePathAccess, false, pid)
	if err != nil {
		return ""
	}
	defer func() { _ = windows.CloseHandle(process) }()
	size := uint32(len(scratch))
	if windows.QueryFullProcessImageName(process, 0, &scratch[0], &size) != nil || size == 0 || size > uint32(len(scratch)) {
		return ""
	}
	return windows.UTF16ToString(scratch[:size])
}
