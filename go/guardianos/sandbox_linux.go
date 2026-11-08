//go:build linux

package guardianos

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// landlockScopeABI is the first Landlock ABI (Linux 6.12) that confines
// abstract Unix sockets and signals to the sandbox's own domain.
const landlockScopeABI = 6

// Apply is called only in the dedicated, trusted child immediately before exec.
// Landlock and seccomp restrict the calling thread and all workload descendants;
// the caller must keep this OS thread locked through exec.
func Apply(profiles []Profile) error {
	if len(profiles) == 0 {
		return nil
	}
	constraints, err := ConstraintsFor(profiles)
	if err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 3 {
		return fmt.Errorf("landlock ABI 3 or later is required")
	}
	if err := supervisorProtection(constraints, int(abi)); err != nil {
		return err
	}
	// The trusted helper's parent is the native supervisor that enforces
	// deadlines, leases and cleanup. The workload must not pause or kill it.
	supervisor := unix.Getppid()
	group, err := unix.Getpgid(supervisor)
	if err != nil || supervisor < 1 || group < 1 {
		return fmt.Errorf("the sandbox supervisor is unavailable")
	}
	// kill(0) signals the caller's own group, so the workload must not share
	// the supervisor's group; the supervisor starts it in a group of its own.
	if unix.Getpgrp() == group {
		return fmt.Errorf("the workload must run in its own process group")
	}
	for _, p := range profiles {
		if err := Validate(p); err != nil {
			return err
		}
		if err := restrictFiles(p, int(abi)); err != nil {
			return err
		}
		if err := installSeccomp(seccompProgram(p.Network == "deny", supervisor, group)); err != nil {
			return err
		}
	}
	return nil
}

// supervisorProtection fails closed when a runtime limit could be defeated.
// A workload running as the supervisor's own user can signal any of its
// threads by ID (kill(2) accepts a thread ID), which seccomp cannot tell apart
// from the workload's own processes. Only Landlock's signal scope (ABI 6,
// Linux 6.12) or a separate workload account stops it from pausing the
// supervisor so the deadline never fires.
func supervisorProtection(constraints Constraints, abi int) error {
	if constraints.Limits.MaxRuntimeSeconds > 0 && constraints.RunAs == nil && abi < landlockScopeABI {
		return errors.New("a runtime limit needs Linux 6.12 or later (Landlock ABI 6) or a separate workload account, so the agent cannot pause Guardian")
	}
	return nil
}

// landlockRulesetAttr is struct landlock_ruleset_attr up to the field this
// package uses. Newer kernels append fields; a shorter size leaves them unset.
type landlockRulesetAttr struct {
	handledAccessFS  uint64
	handledAccessNet uint64
	scoped           uint64
}

func restrictFiles(p Profile, abi int) error {
	// ABI 3 includes every filesystem operation through TRUNCATE and REFER.
	// Newer operations such as device ioctl need separate policy support.
	const handled uint64 = (unix.LANDLOCK_ACCESS_FS_TRUNCATE << 1) - 1
	attr := landlockRulesetAttr{handledAccessFS: handled}
	size := unsafe.Offsetof(attr.handledAccessNet) // ABI 3-5 kernels reject unknown nonzero fields.
	if abi >= landlockScopeABI {
		// Abstract Unix sockets have no filesystem path for Landlock rules. Scope
		// them so the workload reaches only listeners created inside its sandbox,
		// and signal only processes inside it: never the native supervisor.
		attr.scoped = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
		size = unsafe.Sizeof(attr)
	}
	value, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0) // #nosec G103 -- Kernel Landlock ABI reads this exact typed structure synchronously.
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

// Offsets into struct seccomp_data. Arguments are read as their low 32 bits on
// the supported little-endian targets; every argument filtered below is an int
// (or, for clone, a flag word the kernel truncates to 32 bits).
const (
	seccompNR   = 0
	seccompArch = 4
)

func seccompArgument(index uint32) uint32 { return 16 + 8*index }

// ioctlSetOwner is FIOSETOWN, which golang.org/x/sys does not define.
const ioctlSetOwner = 0x8901

func bpfStatement(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

func seccompReturn(value uint32) unix.SockFilter {
	return bpfStatement(unix.BPF_RET|unix.BPF_K, value)
}

var (
	seccompDeny    = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	seccompMissing = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
	seccompLoadNR  = bpfStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompNR)
	seccompAllowed = seccompReturn(unix.SECCOMP_RET_ALLOW)
)

type seccompFilter []unix.SockFilter

// rule runs body only for syscall nr. A body ends either by returning or by
// reloading the syscall number so the following rules can still match.
func (f *seccompFilter) rule(nr uint32, body ...unix.SockFilter) {
	*f = append(*f, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, 0, uint8(len(body))))
	*f = append(*f, body...)
}

func always(result uint32) []unix.SockFilter {
	return []unix.SockFilter{seccompReturn(result)}
}

// whenArgument returns result when (argument & mask) equals one of values.
func whenArgument(index, mask, result uint32, values ...uint32) []unix.SockFilter {
	body := []unix.SockFilter{bpfStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArgument(index))}
	if mask != math.MaxUint32 {
		body = append(body, bpfStatement(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, mask))
	}
	for _, value := range values {
		body = append(body, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, value, 0, 1), seccompReturn(result))
	}
	return append(body, seccompLoadNR)
}

// whenAnyBit returns result when the argument has any of bits set.
func whenAnyBit(index, bits, result uint32) []unix.SockFilter {
	return []unix.SockFilter{
		bpfStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArgument(index)),
		bpfJump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, bits, 0, 1),
		seccompReturn(result),
		seccompLoadNR,
	}
}

// namespaceCloneFlags create namespaces through clone(2). CLONE_NEWTIME shares
// its bit with the exit signal there and exists only for clone3 and unshare.
const namespaceCloneFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

func seccompProgram(denyNetwork bool, supervisor, supervisorGroup int) []unix.SockFilter {
	var architecture uint32
	switch runtime.GOARCH {
	case "amd64":
		architecture = unix.AUDIT_ARCH_X86_64
	case "arm64":
		architecture = unix.AUDIT_ARCH_AARCH64
	default:
		return nil
	}
	filter := seccompFilter{
		bpfStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArch),
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, architecture, 1, 0),
		seccompReturn(unix.SECCOMP_RET_KILL_PROCESS),
		seccompLoadNR,
		// Reject the x32 syscall ABI as well as compatibility architectures.
		bpfJump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, 0x40000000, 0, 1),
		seccompReturn(unix.SECCOMP_RET_KILL_PROCESS),
	}
	// A terminal inherited for interaction must not inject keystrokes into the
	// parent's session or use legacy console commands outside the sandbox.
	// FIOSETOWN and SIOCSPGRP set a file's SIGIO owner through a pointer that
	// seccomp cannot read, so they are refused outright (see fcntl below).
	filter.rule(unix.SYS_IOCTL, whenArgument(1, math.MaxUint32, seccompDeny, unix.TIOCSTI, unix.TIOCLINUX, ioctlSetOwner, unix.SIOCSPGRP)...)
	// unshare and setns are blocked below; clone can create the same namespaces
	// (a new user namespace also reopens kernel attack surface). The kernel
	// reads only the low 32 bits of clone's flags.
	filter.rule(unix.SYS_CLONE, whenAnyBit(0, namespaceCloneFlags, seccompDeny)...)
	// clone3 passes its flags in memory, out of seccomp's reach. ENOSYS is the
	// standard answer: glibc and other runtimes then fall back to clone.
	filter.rule(unix.SYS_CLONE3, always(seccompMissing)...)
	// On every kernel, refuse the direct ways to stop or starve the supervisor:
	// signalling its process (by PID, or by its main thread's ID, which is the
	// same number), its process group or every process at once (kill(-1)),
	// making it the SIGIO owner of a file, taking a pidfd for it, or lowering
	// its resource limits. A pidfd can also come from opening /proc/<pid>, so
	// pidfd_send_signal reports ENOSYS and runtimes fall back to kill, which is
	// filtered. Landlock's signal scope covers its other threads where
	// available; without it a runtime limit fails closed (supervisorProtection).
	self := uint32(int32(supervisor))        // #nosec G115 -- PIDs are positive 32-bit kernel values.
	group := uint32(-int32(supervisorGroup)) // #nosec G115 -- Negative PID addresses the process group.
	everyone := uint32(math.MaxUint32)       // -1
	filter.rule(unix.SYS_KILL, whenArgument(0, math.MaxUint32, seccompDeny, self, group, everyone)...)
	for _, nr := range []uint32{unix.SYS_TKILL, unix.SYS_RT_SIGQUEUEINFO, unix.SYS_TGKILL, unix.SYS_RT_TGSIGQUEUEINFO, unix.SYS_PIDFD_OPEN, unix.SYS_PRLIMIT64} {
		filter.rule(nr, whenArgument(0, math.MaxUint32, seccompDeny, self)...)
	}
	filter.rule(unix.SYS_PIDFD_SEND_SIGNAL, always(seccompMissing)...)
	// Joining the supervisor's group would turn kill(0), which signals the
	// caller's own group, into a signal to the supervisor.
	filter.rule(unix.SYS_SETPGID, whenArgument(1, math.MaxUint32, seccompDeny, uint32(supervisorGroup))...) // #nosec G115 -- Process group IDs are positive 32-bit kernel values.
	// fcntl(fd, F_SETOWN, pid) sends SIGIO, or any signal chosen by F_SETSIG,
	// to pid when the file becomes ready. F_SETOWN_EX names its target (any
	// process or thread) in a structure seccomp cannot read, so it is refused.
	filter.rule(unix.SYS_FCNTL,
		bpfStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArgument(1)),
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.F_SETOWN_EX, 4, 0),
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.F_SETOWN, 0, 4), // otherwise reload the syscall number
		bpfStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArgument(2)),
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, self, 1, 0),
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, group, 0, 1),
		seccompReturn(seccompDeny),
		seccompLoadNR,
	)
	blocked := []uint32{unix.SYS_PTRACE, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PROCESS_VM_READV, unix.SYS_PIDFD_GETFD, unix.SYS_MEMFD_CREATE,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_BPF, unix.SYS_IO_URING_SETUP, unix.SYS_USERFAULTFD,
		unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSMOUNT, unix.SYS_MOUNT_SETATTR,
		unix.SYS_OPEN_TREE, unix.SYS_FSPICK, unix.SYS_FSCONFIG,
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
	} else {
		// Network "inherit" allows IP networking but not host services reached
		// through Unix sockets: the session bus can start programs outside the
		// sandbox through systemd, and Docker, ssh-agent and X11 grant similar
		// power. Landlock cannot restrict connect() to a socket path, so the
		// workload may not create Unix sockets at all. Unnamed stream socketpairs
		// (child stdio in libuv/Node and Python) stay available; a datagram
		// socketpair could be re-addressed to a host socket with sendto().
		filter.rule(unix.SYS_SOCKET, whenArgument(0, math.MaxUint32, seccompDeny, unix.AF_UNIX)...)
		filter.rule(unix.SYS_SOCKETPAIR, whenArgument(1, 0xf, seccompDeny, unix.SOCK_DGRAM)...)
	}
	for _, nr := range blocked {
		filter.rule(nr, always(seccompDeny)...)
	}
	return append(filter, seccompAllowed)
}

func installSeccomp(filter []unix.SockFilter) error {
	filterSize := len(filter)
	if filterSize < 1 || filterSize > math.MaxUint16 {
		return fmt.Errorf("unsupported sandbox architecture or invalid seccomp program size")
	}
	program := unix.SockFprog{Len: uint16(filterSize), Filter: &filter[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&program))) // #nosec G103 -- Kernel seccomp ABI; filter storage is explicitly kept alive below.
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	return nil
}
