package guardianos

import "golang.org/x/sys/unix"

// x86-64 retains pathname variants replaced by *at syscalls on AArch64.
func legacyMetadataSyscalls() []uint32 {
	return []uint32{unix.SYS_CHMOD, unix.SYS_CHOWN, unix.SYS_LCHOWN, unix.SYS_UTIME, unix.SYS_UTIMES, unix.SYS_FUTIMESAT}
}
