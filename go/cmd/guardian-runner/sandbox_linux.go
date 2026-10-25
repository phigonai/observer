//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/phigonai/observer/go/guardianos"
	"golang.org/x/sys/unix"
)

func runSandboxChild(args []string) int {
	runtime.LockOSThread()
	if len(args) < 5 || !filepath.IsAbs(args[2]) || !filepath.IsAbs(args[4]) {
		return fail(nil)
	}
	stdioPeer, err := strconv.Atoi(args[3])
	if err != nil || stdioPeer <= 1 {
		return fail(fmt.Errorf("invalid standard-stream peer identity"))
	}
	profiles, err := guardianos.Parse(args[0])
	if err != nil || len(profiles) == 0 {
		return fail(err)
	}
	if !guardSandboxStdio(profiles, stdioPeer) {
		return 77
	}
	constraints, err := guardianos.ConstraintsFor(profiles)
	if err != nil {
		return fail(err)
	}
	if identity := constraints.RunAs; identity != nil {
		groups, err := os.Getgroups()
		if err != nil || int64(os.Getuid()) != int64(identity.UID) || int64(os.Geteuid()) != int64(identity.UID) || int64(os.Getgid()) != int64(identity.GID) || int64(os.Getegid()) != int64(identity.GID) || len(groups) != 0 {
			return fail(fmt.Errorf("required workload identity was not established"))
		}
	}
	// Remove any capabilities retained by host configuration or file xattrs.
	// no_new_privs in Apply also prevents regaining them through later execs.
	caps := [2]unix.CapUserData{}
	if err := unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &caps[0]); err != nil {
		return fail(fmt.Errorf("could not clear workload capabilities: %w", err))
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fail(fmt.Errorf("could not clear ambient workload capabilities: %w", err))
	}
	fd, err := unix.Open(args[4], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fail(err)
	}
	file := os.NewFile(uintptr(fd), args[4])
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil || hex.EncodeToString(hash.Sum(nil)) != args[1] {
		return fail(err)
	}
	if err = os.Chdir(args[2]); err != nil {
		return fail(err)
	}
	if err = guardianos.Apply(profiles); err != nil {
		fmt.Fprintln(os.Stderr, "Phigon Guardian: required OS sandbox could not be enforced:", err)
		return 77
	}
	// Execute the reviewed open inode, preventing path replacement between the
	// final hash and exec. Workloads use explicit native interpreters for scripts.
	err = unix.Exec("/proc/self/fd/"+strconv.Itoa(fd), args[4:], os.Environ())
	return fail(err)
}

// Also checked by the parent before spawning the sandbox helper, so even
// helper initialization errors cannot write into a redirected protected file.
func guardSandboxStdio(profiles []guardianos.Profile, peerPID int) bool {
	denyNetwork := false
	for _, profile := range profiles {
		denyNetwork = denyNetwork || profile.Network == "deny"
	}
	for fd := 0; fd < 3; fd++ {
		if err := validateSandboxStream(fd, denyNetwork, peerPID); err != nil {
			if validateSandboxStream(2, true, peerPID) == nil {
				reportTermination("Phigon Guardian: " + err.Error())
			}
			return false
		}
	}
	return true
}

func validateSandboxStream(fd int, denyNetwork bool, peerPID int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("invalid standard stream: %w", err)
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFIFO:
		// Explicit data pipes do not carry an ambient file/device handle.
	case unix.S_IFSOCK:
		if denyNetwork && !observerStreamSocket(fd, peerPID) {
			return fmt.Errorf("network sockets cannot be inherited as standard streams")
		}
	case unix.S_IFCHR:
		if unix.Major(uint64(stat.Rdev)) == 1 && unix.Minor(uint64(stat.Rdev)) == 3 {
			return nil
		} // /dev/null
		if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err != nil {
			return fmt.Errorf("device handles cannot be inherited as standard streams")
		}
	default:
		// Landlock checks access when a file is opened, not on reads/writes
		// through a file descriptor inherited from before the sandbox.
		return fmt.Errorf("file handles cannot be inherited as standard streams; open approved files inside the sandbox")
	}
	return nil
}

// libuv uses unnamed Unix stream socketpairs for subprocess "pipes". Permit
// only this data channel to the original observer, never TCP, named/abstract
// Unix services, datagrams, or socketpairs owned by an unrelated process.
func observerStreamSocket(fd, peerPID int) bool {
	// Preserve sockaddr length: text conversions can represent both an unnamed
	// socket and an empty abstract socket as "@", losing the required distinction.
	for _, call := range []uintptr{unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME} {
		var address unix.RawSockaddrUnix
		length := uint32(unix.SizeofSockaddrUnix)
		_, _, errno := unix.Syscall(call, uintptr(fd), uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Pointer(&length))) // #nosec G103 -- Synchronous kernel sockaddr ABI; both typed buffers and length remain live through the call.
		if errno != 0 || length != 2 || address.Family != unix.AF_UNIX {
			return false
		}
	}
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_STREAM {
		return false
	}
	credentials, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	return err == nil && peerPID > 1 && int(credentials.Pid) == peerPID
}
