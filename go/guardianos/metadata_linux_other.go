//go:build linux && !amd64

package guardianos

// AArch64 has no legacy pathname metadata syscalls. Other architectures are
// rejected before installing a seccomp filter.
func legacyMetadataSyscalls() []uint32 { return nil }
