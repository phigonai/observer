//go:build linux

package guardianos

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Seccomp and Landlock cannot be removed once applied, so every check runs in
// a fresh copy of this test binary that sandboxes itself and reports back.
const sandboxCheckVariable = "PHIGON_GUARDIANOS_SANDBOX_CHECK"

type sandboxCheck struct {
	network string
	limits  *Limits
	run     func() error
}

var sandboxChecks = map[string]sandboxCheck{
	"inherit-blocks-unix-sockets": {network: "inherit", run: func() error {
		return errors.Join(
			expectErrno("socket(AF_UNIX, SOCK_STREAM)", unix.EPERM, func() error { return closeSocket(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)) }),
			expectErrno("socket(AF_UNIX, SOCK_DGRAM)", unix.EPERM, func() error { return closeSocket(unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)) }),
			expectErrno("socketpair(AF_UNIX, SOCK_DGRAM)", unix.EPERM, func() error { return closePair(unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)) }),
			expectErrno("socketpair(AF_UNIX, SOCK_STREAM)", 0, func() error { return closePair(unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)) }),
			expectErrno("socketpair(AF_UNIX, SOCK_SEQPACKET)", 0, func() error {
				return closePair(unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0))
			}),
			expectErrno("socket(AF_INET, SOCK_STREAM)", 0, func() error { return closeSocket(unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)) }),
			expectErrno("socket(AF_INET6, SOCK_DGRAM)", 0, func() error {
				err := closeSocket(unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0))
				if errors.Is(err, unix.EAFNOSUPPORT) {
					return nil // IPv6 disabled on this host; not a sandbox decision.
				}
				return err
			}),
		)
	}},
	"deny-blocks-all-sockets": {network: "deny", run: func() error {
		return errors.Join(
			expectErrno("socket(AF_INET, SOCK_STREAM)", unix.EPERM, func() error { return closeSocket(unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)) }),
			expectErrno("socketpair(AF_UNIX, SOCK_STREAM)", unix.EPERM, func() error { return closePair(unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)) }),
		)
	}},
}

func init() {
	sandboxChecks["namespaces-blocked"] = sandboxCheck{network: "inherit", run: func() error {
		failures := []error{
			expectErrno("clone3", unix.ENOSYS, func() error {
				_, _, errno := unix.Syscall(unix.SYS_CLONE3, 0, 0, 0)
				if errno != 0 {
					return errno
				}
				return nil
			}),
		}
		for _, flag := range []uintptr{unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWPID, unix.CLONE_NEWNET, unix.CLONE_NEWUTS, unix.CLONE_NEWIPC, unix.CLONE_NEWCGROUP} {
			failures = append(failures, expectErrno(fmt.Sprintf("clone(%#x)", flag), unix.EPERM, func() error {
				return startAndWait("/usr/bin/true", &syscall.SysProcAttr{Cloneflags: flag})
			}))
		}
		// Ordinary process creation keeps working: Go's clone, and glibc's
		// clone3 users (threads, posix_spawn) through their clone fallback.
		failures = append(failures, expectErrno("fork and exec", 0, func() error { return startAndWait("/usr/bin/true", nil) }))
		if _, err := os.Stat("/usr/bin/python3"); err == nil {
			failures = append(failures, expectErrno("threads and subprocesses in a glibc program", 0, func() error {
				return startAndWait("/usr/bin/python3", nil, "-S", "-c",
					"import subprocess,threading;t=threading.Thread(target=print);t.start();t.join();subprocess.run(['/usr/bin/true'],check=True)")
			}))
		}
		return errors.Join(failures...)
	}}
}

func init() {
	sandboxChecks["supervisor-protected"] = sandboxCheck{network: "inherit", run: func() error {
		supervisor := unix.Getppid()
		group, err := unix.Getpgid(supervisor)
		if err != nil {
			return err
		}
		var limit unix.Rlimit
		var pipe [2]int
		if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
			return err
		}
		syscall3 := func(nr, a, b, c uintptr) error {
			if _, _, errno := unix.Syscall(nr, a, b, c); errno != 0 {
				return errno
			}
			return nil
		}
		owner := func(pid int) error { return syscall3(unix.SYS_FCNTL, uintptr(pipe[0]), unix.F_SETOWN, uintptr(pid)) }
		return errors.Join(
			// The supervisor's main thread ID is its PID.
			expectErrno("tkill(supervisor)", unix.EPERM, func() error { return syscall3(unix.SYS_TKILL, uintptr(supervisor), 0, 0) }),
			expectErrno("tkill(own thread)", 0, func() error { return syscall3(unix.SYS_TKILL, uintptr(unix.Gettid()), 0, 0) }),
			expectErrno("pidfd_send_signal", unix.ENOSYS, func() error {
				fd, err := unix.PidfdOpen(unix.Getpid(), 0)
				if err != nil {
					return err
				}
				defer unix.Close(fd)
				return unix.PidfdSendSignal(fd, 0, nil, 0)
			}),
			expectErrno("fcntl(F_SETOWN, supervisor)", unix.EPERM, func() error { return owner(supervisor) }),
			expectErrno("fcntl(F_SETOWN, supervisor group)", unix.EPERM, func() error { return owner(-group) }),
			expectErrno("fcntl(F_SETOWN, self)", 0, func() error { return owner(unix.Getpid()) }),
			expectErrno("fcntl(F_SETOWN_EX)", unix.EPERM, func() error {
				// struct f_owner_ex{F_OWNER_TID, tid}: aimed at the workload's own thread,
				// it is still refused, since seccomp cannot see whose thread it names.
				target := struct{ kind, pid int32 }{0, int32(unix.Gettid())}
				return syscall3(unix.SYS_FCNTL, uintptr(pipe[0]), unix.F_SETOWN_EX, uintptr(unsafe.Pointer(&target)))
			}),
			expectErrno("ioctl(FIOSETOWN)", unix.EPERM, func() error {
				self := int32(unix.Getpid())
				return syscall3(unix.SYS_IOCTL, uintptr(pipe[0]), ioctlSetOwner, uintptr(unsafe.Pointer(&self)))
			}),
			expectErrno("fcntl(F_SETSIG) for a file the workload owns", 0, func() error {
				return syscall3(unix.SYS_FCNTL, uintptr(pipe[0]), unix.F_SETSIG, uintptr(unix.SIGUSR1))
			}),
			expectErrno("fcntl(F_GETFL)", 0, func() error { return syscall3(unix.SYS_FCNTL, uintptr(pipe[0]), unix.F_GETFL, 0) }),
			expectErrno("fcntl(F_DUPFD_CLOEXEC)", 0, func() error {
				fd, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(pipe[0]), unix.F_DUPFD_CLOEXEC, 0)
				if errno != 0 {
					return errno
				}
				return unix.Close(int(fd))
			}),
			expectErrno("kill(supervisor)", unix.EPERM, func() error { return unix.Kill(supervisor, 0) }),
			expectErrno("kill(supervisor group)", unix.EPERM, func() error { return unix.Kill(-group, 0) }),
			expectErrno("kill(-1)", unix.EPERM, func() error { return unix.Kill(-1, 0) }),
			expectErrno("tgkill(supervisor)", unix.EPERM, func() error { return unix.Tgkill(supervisor, supervisor, 0) }),
			expectErrno("pidfd_open(supervisor)", unix.EPERM, func() error { return closeSocket(unix.PidfdOpen(supervisor, 0)) }),
			expectErrno("prlimit(supervisor)", unix.EPERM, func() error { return unix.Prlimit(supervisor, unix.RLIMIT_CPU, nil, &limit) }),
			expectErrno("setpgid(supervisor group)", unix.EPERM, func() error { return unix.Setpgid(0, group) }),
			expectErrno("setpgid(new group)", 0, func() error { return unix.Setpgid(0, 0) }),
			expectErrno("kill(self)", 0, func() error { return unix.Kill(unix.Getpid(), 0) }),
			expectErrno("kill(own group)", 0, func() error { return unix.Kill(0, 0) }),
			expectErrno("prlimit(self)", 0, func() error { return unix.Prlimit(0, unix.RLIMIT_CPU, nil, &limit) }),
		)
	}}
	sandboxChecks["runtime-limit"] = sandboxCheck{network: "inherit", limits: &Limits{MaxRuntimeSeconds: 5}, run: func() error { return nil }}
}

// startAndWait starts path without Go's os/exec helpers, so the clone flags
// requested are exactly the ones the kernel sees.
func startAndWait(path string, attributes *syscall.SysProcAttr, arguments ...string) error {
	pid, err := syscall.ForkExec(path, append([]string{path}, arguments...), &syscall.ProcAttr{Env: []string{"PATH=/usr/bin"}, Files: []uintptr{0, 1, 2}, Sys: attributes})
	if err != nil {
		return err
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
		return err
	}
	if !status.Exited() || status.ExitStatus() != 0 {
		return fmt.Errorf("%s ended with %v", path, status)
	}
	return nil
}

func TestMain(m *testing.M) {
	if name := os.Getenv(sandboxCheckVariable); name != "" {
		os.Exit(runSandboxCheck(name))
	}
	os.Exit(m.Run())
}

func runSandboxCheck(name string) int {
	check, ok := sandboxChecks[name]
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown sandbox check", name)
		return 2
	}
	// Landlock and seccomp apply to the calling thread; keep every check on it.
	runtime.LockOSThread()
	profile := Profile{Name: "Kernel check", Platform: "linux", ReadPaths: []string{"/usr"}, ExecutePaths: []string{"/usr"}, Network: check.network, Limits: check.limits}
	if err := Apply([]Profile{profile}); err != nil {
		fmt.Fprintln(os.Stderr, "APPLY:", err)
		return 3
	}
	if err := check.run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("OK")
	return 0
}

func landlockABI() int {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(abi)
}

// runSandboxed runs one named check in a sandboxed child and returns its exit
// code and combined output.
func runSandboxed(t *testing.T, name string) (int, string) {
	t.Helper()
	if landlockABI() < 3 {
		t.Skip("this kernel has no Landlock ABI 3; the runner refuses sandboxed launches here")
	}
	command := exec.Command(os.Args[0], "-test.run=^$")
	command.Env = append(os.Environ(), sandboxCheckVariable+"="+name)
	// Like the runner's workload, the child leads its own process group.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output, err := command.CombinedOutput()
	code := 0
	if exit := (*exec.ExitError)(nil); errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(output)
}

func requireSandboxCheck(t *testing.T, name string) {
	t.Helper()
	code, output := runSandboxed(t, name)
	if code != 0 || !strings.Contains(output, "OK") {
		t.Fatalf("sandbox check %s failed (exit %d):\n%s", name, code, output)
	}
}

func TestInheritedNetworkCannotReachHostUnixServices(t *testing.T) {
	requireSandboxCheck(t, "inherit-blocks-unix-sockets")
}

func TestCloneCannotCreateNamespaces(t *testing.T) {
	requireSandboxCheck(t, "namespaces-blocked")
}

func TestWorkloadCannotSignalOrLimitItsSupervisor(t *testing.T) {
	requireSandboxCheck(t, "supervisor-protected")
}

// Without Landlock's signal scope a same-user workload can still pause the
// supervisor through one of its thread IDs, so a deadline must not be promised.
func TestRuntimeLimitFailsClosedWithoutSignalScope(t *testing.T) {
	code, output := runSandboxed(t, "runtime-limit")
	if landlockABI() >= landlockScopeABI {
		if code != 0 {
			t.Fatalf("runtime limit should be enforceable with Landlock ABI %d: %s", landlockABI(), output)
		}
		return
	}
	if code != 3 || !strings.Contains(output, "Linux 6.12") {
		t.Fatalf("runtime limit on Landlock ABI %d must fail closed (exit %d): %s", landlockABI(), code, output)
	}
}

func TestSupervisorProtectionPolicy(t *testing.T) {
	deadline := Constraints{Limits: Limits{MaxRuntimeSeconds: 60}}
	separate := Constraints{Limits: Limits{MaxRuntimeSeconds: 60}, RunAs: &UnixIdentity{UID: 1001, GID: 1001}}
	for _, test := range []struct {
		name        string
		constraints Constraints
		abi         int
		allowed     bool
	}{
		{"deadline without signal scope", deadline, 5, false},
		{"deadline with signal scope", deadline, 6, true},
		{"deadline for a separate account", separate, 3, true},
		{"no deadline", Constraints{Limits: Limits{MaxMemoryBytes: 64 << 20}}, 3, true},
	} {
		if err := supervisorProtection(test.constraints, test.abi); (err == nil) != test.allowed {
			t.Errorf("%s: allowed=%v err=%v", test.name, test.allowed, err)
		}
	}
}

func TestDeniedNetworkStillBlocksEverySocket(t *testing.T) {
	requireSandboxCheck(t, "deny-blocks-all-sockets")
}

func expectErrno(name string, want unix.Errno, call func() error) error {
	err := call()
	if want == 0 {
		if err != nil {
			return fmt.Errorf("%s should be allowed: %v", name, err)
		}
		return nil
	}
	if !errors.Is(err, want) {
		return fmt.Errorf("%s: want %v, got %v", name, want, err)
	}
	return nil
}

func closeSocket(fd int, err error) error {
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

func closePair(fds [2]int, err error) error {
	if err == nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	}
	return err
}

func init() {
	sandboxChecks["shared-group"] = sandboxCheck{network: "inherit", run: func() error { return nil }}
}

// A workload left in the supervisor's process group could signal it with
// kill(0), so the sandbox refuses to start there.
func TestWorkloadInTheSupervisorsGroupIsRefused(t *testing.T) {
	if landlockABI() < 3 {
		t.Skip("this kernel has no Landlock ABI 3; the runner refuses sandboxed launches here")
	}
	command := exec.Command(os.Args[0], "-test.run=^$")
	command.Env = append(os.Environ(), sandboxCheckVariable+"=shared-group")
	output, err := command.CombinedOutput()
	if exit := (*exec.ExitError)(nil); !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(string(output), "own process group") {
		t.Fatalf("a workload sharing the supervisor's group was sandboxed: %v %s", err, output)
	}
}
