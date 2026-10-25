//go:build linux

package guardianos

import (
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Apply is called only in the dedicated, trusted child immediately before exec.
// Landlock and seccomp restrict the calling thread and all workload descendants;
// the caller must keep this OS thread locked through exec.
func Apply(profiles []Profile) error {
	if len(profiles) == 0 {
		return nil
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 3 {
		return fmt.Errorf("landlock ABI 3 or later is required")
	}
	for _, p := range profiles {
		if err := Validate(p); err != nil {
			return err
		}
		if err := restrictFiles(p); err != nil {
			return err
		}
		if err := restrictSyscalls(p.Network == "deny"); err != nil {
			return err
		}
	}
	return nil
}

func restrictFiles(p Profile) error {
	// ABI 3 includes every filesystem operation through TRUNCATE and REFER.
	// Newer operations such as device ioctl need separate policy support.
	const handled uint64 = (unix.LANDLOCK_ACCESS_FS_TRUNCATE << 1) - 1
	attr := struct{ Access uint64 }{handled}
	value, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0) // #nosec G103 -- Kernel Landlock ABI reads this exact typed structure synchronously.
	if errno != 0 {
		return errno
	}
	ruleset := int(value)
	defer unix.Close(ruleset)
	read := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	write := handled &^ uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE|unix.LANDLOCK_ACCESS_FS_MAKE_CHAR|unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK|unix.LANDLOCK_ACCESS_FS_MAKE_SOCK)
	for _, group := range []struct {
		paths  []string
		rights uint64
	}{{p.ReadPaths, read}, {p.WritePaths, write}, {p.ExecutePaths, uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE)}} {
		for _, path := range group.paths {
			fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
			if err != nil {
				return fmt.Errorf("open OS rule path: %w", err)
			}
			if fd < 0 || int64(fd) > math.MaxInt32 {
				_ = unix.Close(fd)
				return fmt.Errorf("invalid Landlock descriptor")
			}
			var stat unix.Stat_t
			if err = unix.Fstat(fd, &stat); err != nil {
				_ = unix.Close(fd)
				return err
			}
			rights := group.rights
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
				if stat.Mode&unix.S_IFMT != unix.S_IFREG {
					_ = unix.Close(fd)
					return fmt.Errorf("OS rule path must be a regular file or directory")
				}
				rights &= unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE
			}
			beneath := struct {
				Access  uint64
				FD      int32
				Padding uint32
			}{Access: rights, FD: int32(fd)}
			_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&beneath)), 0, 0, 0) // #nosec G103 -- Landlock ABI requires the typed path-beneath structure address.
			_ = unix.Close(fd)
			if errno != 0 {
				return errno
			}
		}
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func restrictSyscalls(denyNetwork bool) error {
	var architecture uint32
	switch runtime.GOARCH {
	case "amd64":
		architecture = unix.AUDIT_ARCH_X86_64
	case "arm64":
		architecture = unix.AUDIT_ARCH_AARCH64
	default:
		return fmt.Errorf("unsupported sandbox architecture")
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: architecture, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		// Reject the x32 syscall ABI as well as compatibility architectures.
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 0x40000000, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
	}
	// A terminal inherited for interaction must not inject keystrokes into the
	// parent's session or use legacy console commands outside the sandbox.
	filter = append(filter,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_IOCTL, Jf: 5},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 24}, // args[1], low 32 bits on supported little-endian targets
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.TIOCSTI, Jf: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.TIOCLINUX, Jf: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	)
	blocked := []uint32{unix.SYS_PTRACE, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PROCESS_VM_READV, unix.SYS_PIDFD_GETFD, unix.SYS_MEMFD_CREATE,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_BPF, unix.SYS_IO_URING_SETUP, unix.SYS_USERFAULTFD,
		unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSMOUNT, unix.SYS_MOUNT_SETATTR,
		// Landlock does not mediate these metadata mutations. A caller could
		// otherwise chmod/chown a protected file without opening it for writing.
		unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2,
		unix.SYS_FCHOWN, unix.SYS_FCHOWNAT, unix.SYS_UTIMENSAT,
		unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_FSETXATTR, unix.SYS_SETXATTRAT,
		unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR, unix.SYS_FREMOVEXATTR, unix.SYS_REMOVEXATTRAT}
	blocked = append(blocked, legacyMetadataSyscalls()...)
	if denyNetwork {
		blocked = append(blocked, unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_BIND,
			unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_SENDTO, unix.SYS_SENDMSG, unix.SYS_SENDMMSG)
	}
	for _, nr := range blocked {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: nr, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	filterSize := len(filter)
	if filterSize < 1 || filterSize > math.MaxUint16 {
		return fmt.Errorf("invalid seccomp program size")
	}
	program := unix.SockFprog{Len: uint16(filterSize), Filter: &filter[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&program))) // #nosec G103 -- Kernel seccomp ABI; filter storage is explicitly kept alive below.
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	return nil
}
