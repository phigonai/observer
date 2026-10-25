//go:build linux

package linuxsupervisor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	childModeArgument = "__child"
	readyFD           = 3
	gateFD            = 4
	specFD            = 5
)

type Launcher struct {
	config Config
	sensor *MembershipSensor
}

type childLaunchSpec struct {
	Path           string   `json:"path"`
	Args           []string `json:"args"`
	CgroupRoot     string   `json:"cgroup_root"`
	ProcRoot       string   `json:"proc_root"`
	MachineID      string   `json:"machine_id"`
	BoundaryID     string   `json:"boundary_id"`
	NativeIdentity string   `json:"native_identity"`
}

func NewLauncher(config Config) (*Launcher, error) {
	if strings.TrimSpace(config.MachineID) == "" {
		return nil, fmt.Errorf("machine identity is required")
	}
	if _, err := resolveBoundaryPath(config.CgroupRoot, "validation"); err != nil {
		return nil, err
	}
	if _, err := resolveProcPath(config.ProcRoot, "self", "stat"); err != nil {
		return nil, err
	}
	if config.HelperPath == "" || !filepath.IsAbs(config.HelperPath) {
		return nil, fmt.Errorf("absolute supervisor helper path is required")
	}
	helper, err := os.Lstat(config.HelperPath)
	if err != nil || helper.Mode()&os.ModeSymlink != 0 ||
		!helper.Mode().IsRegular() || helper.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("supervisor helper is not executable")
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = 5 * time.Second
	}
	if config.HandshakeTimeout > time.Minute {
		return nil, fmt.Errorf("handshake timeout exceeds one minute")
	}
	sensor, err := NewMembershipSensor(SensorConfig{
		CgroupRoot: config.CgroupRoot,
		ProcRoot:   config.ProcRoot,
		MachineID:  config.MachineID,
	})
	if err != nil {
		return nil, err
	}
	return &Launcher{config: config, sensor: sensor}, nil
}

// CreateBoundary creates exactly one directory beneath the configured,
// delegated cgroup-v2 root. openat plus O_NOFOLLOW prevents symlink traversal.
func (l *Launcher) CreateBoundary(boundaryID string) (*Boundary, error) {
	path, err := resolveBoundaryPath(l.config.CgroupRoot, boundaryID)
	if err != nil {
		return nil, err
	}
	rootFD, err := openCgroupRoot(l.config.CgroupRoot)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	if err := unix.Mkdirat(rootFD, boundaryID, 0o700); err != nil {
		return nil, fmt.Errorf("create delegated cgroup boundary: %w", err)
	}
	boundaryFD, err := unix.Openat(
		rootFD,
		boundaryID,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		_ = unix.Unlinkat(rootFD, boundaryID, unix.AT_REMOVEDIR)
		return nil, fmt.Errorf("open delegated cgroup boundary: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Close(boundaryFD)
			_ = unix.Unlinkat(rootFD, boundaryID, unix.AT_REMOVEDIR)
		}
	}()
	if err := verifyCgroupV2FD(boundaryFD); err != nil {
		return nil, err
	}
	procsFD, err := unix.Openat(
		boundaryFD,
		"cgroup.procs",
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("delegated cgroup has no readable membership file: %w", err)
	}
	_ = unix.Close(procsFD)
	var stat unix.Stat_t
	if err := unix.Fstat(boundaryFD, &stat); err != nil {
		return nil, fmt.Errorf("read cgroup identity: %w", err)
	}
	hash := sha256.Sum256([]byte(path))
	boundary := &Boundary{
		ID:             boundaryID,
		NativeIdentity: fmt.Sprintf("cgroupv2:%d:%d", uint64(stat.Dev), stat.Ino),
		PathDigest:     hex.EncodeToString(hash[:]),
		root:           filepath.Clean(l.config.CgroupRoot),
		path:           path,
		fd:             boundaryFD,
	}
	cleanup = false
	return boundary, nil
}

// Launch starts the small helper atomically inside the cgroup using
// CLONE_INTO_CGROUP through Go's UseCgroupFD. The helper waits before exec;
// both child and parent independently verify membership and process identity.
func (l *Launcher) Launch(
	ctx context.Context,
	boundary *Boundary,
	spec LaunchSpec,
) (*LaunchedProcess, error) {
	if boundary == nil || boundary.fd < 0 || boundary.root != filepath.Clean(l.config.CgroupRoot) {
		return nil, fmt.Errorf("%w: boundary was not created by this launcher", ErrInvalidBoundary)
	}
	lifecycle := NewLifecycle()
	if err := lifecycle.BoundaryReady(boundary); err != nil {
		return nil, err
	}
	targetPath, args, err := validatedCommand(spec.Path, spec.Args)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(childLaunchSpec{
		Path:           targetPath,
		Args:           args,
		CgroupRoot:     l.config.CgroupRoot,
		ProcRoot:       l.config.ProcRoot,
		MachineID:      l.config.MachineID,
		BoundaryID:     boundary.ID,
		NativeIdentity: boundary.NativeIdentity,
	})
	if err != nil || len(payload) > maxLaunchSpecBytes {
		return nil, fmt.Errorf("launch specification exceeds safe bounds")
	}

	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		_ = readyRead.Close()
		_ = readyWrite.Close()
		return nil, err
	}
	specRead, specWrite, err := os.Pipe()
	if err != nil {
		_ = readyRead.Close()
		_ = readyWrite.Close()
		_ = gateRead.Close()
		_ = gateWrite.Close()
		return nil, err
	}
	defer readyRead.Close()
	defer gateWrite.Close()
	defer specWrite.Close()

	command := exec.CommandContext(ctx, l.config.HelperPath, childModeArgument) // #nosec G204 -- Validated operator-owned helper path, fixed child-mode argument, no shell.
	command.Args = []string{l.config.HelperPath, childModeArgument}
	command.Env = spec.Env
	command.Dir = spec.Dir
	command.Stdin = spec.Stdin
	command.Stdout = spec.Stdout
	command.Stderr = spec.Stderr
	command.ExtraFiles = []*os.File{readyWrite, gateRead, specRead}
	pidFD := -1
	command.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig:   syscall.SIGKILL,
		UseCgroupFD: true,
		CgroupFD:    boundary.fd,
		PidFD:       &pidFD,
	}
	if err := command.Start(); err != nil {
		closeChildPipeEnds(readyWrite, gateRead, specRead)
		return nil, fmt.Errorf("start supervisor helper in cgroup: %w", err)
	}
	closeChildPipeEnds(readyWrite, gateRead, specRead)
	if pidFD >= 0 {
		defer unix.Close(pidFD)
	}

	payloadErr := make(chan error, 1)
	go func() {
		_, writeErr := specWrite.Write(payload)
		if closeErr := specWrite.Close(); writeErr == nil {
			writeErr = closeErr
		}
		payloadErr <- writeErr
	}()

	readyLine, err := waitForReady(ctx, readyRead, l.config.HandshakeTimeout)
	if err != nil {
		abortProcess(command)
		return nil, fmt.Errorf("supervisor helper did not verify membership: %w", err)
	}
	if writeErr := <-payloadErr; writeErr != nil {
		abortProcess(command)
		return nil, fmt.Errorf("send private launch specification: %w", writeErr)
	}
	const readyPrefix = "READY "
	if !strings.HasPrefix(readyLine, readyPrefix) {
		abortProcess(command)
		return nil, fmt.Errorf("supervisor helper returned an invalid handshake")
	}
	childKey := strings.TrimSpace(strings.TrimPrefix(readyLine, readyPrefix))
	if err := verifyPIDInBoundaryFD(boundary.fd, command.Process.Pid); err != nil {
		lifecycle.Degrade("kernel cgroup membership file did not contain the helper")
		abortProcess(command)
		return nil, err
	}
	coverage := l.sensor.Observe(boundary, command.Process.Pid)
	if !coverage.VerifiedForLaunch() {
		lifecycle.Degrade(coverage.Reason)
		abortProcess(command)
		return nil, fmt.Errorf("%w: %s", ErrCoverageIncomplete, coverage.Reason)
	}
	identity, ok := identityForPID(coverage.Members, command.Process.Pid)
	if !ok || identity.StableKey == "" || identity.StableKey != childKey {
		lifecycle.Degrade("parent and child stable process identities disagree")
		abortProcess(command)
		return nil, fmt.Errorf("%w: stable process identity mismatch", ErrMembershipMismatch)
	}
	if err := lifecycle.MembershipVerified(coverage); err != nil {
		abortProcess(command)
		return nil, err
	}
	if _, err := gateWrite.Write([]byte{'G'}); err != nil {
		abortProcess(command)
		return nil, fmt.Errorf("release verified supervisor helper: %w", err)
	}
	if err := gateWrite.Close(); err != nil {
		abortProcess(command)
		return nil, fmt.Errorf("close supervisor handshake: %w", err)
	}
	if err := lifecycle.LaunchVerified(identity.StableKey); err != nil {
		abortProcess(command)
		return nil, err
	}
	return &LaunchedProcess{
		Command:          command,
		Identity:         identity,
		Coverage:         coverage,
		Boundary:         boundary,
		BoundaryVerified: true,
	}, nil
}

// ConfigureCommand installs atomic cgroup placement on an existing command.
// Guardian uses this after consuming its centrally authorized launch grant.
func (l *Launcher) ConfigureCommand(boundary *Boundary, command *exec.Cmd) error {
	if boundary == nil || boundary.fd < 0 || boundary.root != filepath.Clean(l.config.CgroupRoot) {
		return ErrInvalidBoundary
	}
	if err := verifyCgroupV2FD(boundary.fd); err != nil {
		return err
	}
	// Verify the containment primitive is writable without firing it before
	// launch. Older kernels kill new CLONE_INTO_CGROUP children when cgroup.kill
	// has already been written, even if that earlier boundary was empty.
	killFD, err := unix.Openat(boundary.fd, "cgroup.kill", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("cgroup termination is unavailable: %w", err)
	}
	if err := unix.Close(killFD); err != nil {
		return err
	}
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: boundary.fd, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	return nil
}

// KillBoundary terminates all remaining descendants through the original open
// cgroup descriptor, including processes that have created a new session.
func (l *Launcher) KillBoundary(boundary *Boundary) error {
	if boundary == nil || boundary.fd < 0 || boundary.root != filepath.Clean(l.config.CgroupRoot) {
		return ErrInvalidBoundary
	}
	fd, err := unix.Openat(boundary.fd, "cgroup.kill", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = unix.Write(fd, []byte("1"))
	return err
}

// RemoveBoundary removes an empty boundary created by this launcher. It never
// kills processes and therefore fails if any process is still present.
func (l *Launcher) RemoveBoundary(boundary *Boundary) error {
	if boundary == nil || boundary.root != filepath.Clean(l.config.CgroupRoot) ||
		validateBoundaryID(boundary.ID) != nil {
		return ErrInvalidBoundary
	}
	if boundary.fd >= 0 {
		if err := unix.Close(boundary.fd); err != nil {
			return err
		}
		boundary.fd = -1
	}
	rootFD, err := openCgroupRoot(l.config.CgroupRoot)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	if err := unix.Unlinkat(rootFD, boundary.ID, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove empty cgroup boundary: %w", err)
	}
	return nil
}

// RunChildHandshake is invoked only by the dedicated supervisor command's
// hidden child mode. It verifies itself before replacing the helper image with
// the operator-approved target.
func RunChildHandshake() error {
	ready := os.NewFile(readyFD, "supervisor-ready")
	gate := os.NewFile(gateFD, "supervisor-gate")
	specFile := os.NewFile(specFD, "supervisor-spec")
	if ready == nil || gate == nil || specFile == nil {
		return fmt.Errorf("supervisor handshake descriptors are unavailable")
	}
	defer ready.Close()
	defer gate.Close()
	defer specFile.Close()
	decoder := json.NewDecoder(io.LimitReader(specFile, maxLaunchSpecBytes+1))
	decoder.DisallowUnknownFields()
	var spec childLaunchSpec
	if err := decoder.Decode(&spec); err != nil {
		return fmt.Errorf("decode private launch specification: %w", err)
	}
	if len(spec.Args) == 0 || spec.Args[0] != spec.Path {
		return fmt.Errorf("private launch specification has an invalid argument vector")
	}
	validatedPath, validatedArgs, err := validatedCommand(spec.Path, spec.Args[1:])
	if err != nil || validatedPath != spec.Path || !equalStrings(validatedArgs, spec.Args) {
		if err != nil {
			return err
		}
		return fmt.Errorf("private launch specification changed during validation")
	}
	boundaryFD, observedIdentity, err := openExistingBoundary(spec.CgroupRoot, spec.BoundaryID)
	if err != nil {
		return err
	}
	defer unix.Close(boundaryFD)
	if observedIdentity != spec.NativeIdentity {
		return fmt.Errorf("%w: native cgroup identity changed", ErrMembershipMismatch)
	}
	if err := verifyPIDInBoundaryFD(boundaryFD, os.Getpid()); err != nil {
		return err
	}
	boundaryPath, err := resolveBoundaryPath(spec.CgroupRoot, spec.BoundaryID)
	if err != nil {
		return err
	}
	boundary := &Boundary{
		ID:             spec.BoundaryID,
		NativeIdentity: spec.NativeIdentity,
		root:           filepath.Clean(spec.CgroupRoot),
		path:           boundaryPath,
		fd:             boundaryFD,
	}
	sensor, err := NewMembershipSensor(SensorConfig{
		CgroupRoot: spec.CgroupRoot,
		ProcRoot:   spec.ProcRoot,
		MachineID:  spec.MachineID,
	})
	if err != nil {
		return err
	}
	coverage := sensor.Observe(boundary, os.Getpid())
	if !coverage.VerifiedForLaunch() {
		return fmt.Errorf("%w: %s", ErrCoverageIncomplete, coverage.Reason)
	}
	identity, ok := identityForPID(coverage.Members, os.Getpid())
	if !ok || identity.StableKey == "" {
		return ErrMembershipMismatch
	}
	if _, err := fmt.Fprintf(ready, "READY %s\n", identity.StableKey); err != nil {
		return err
	}
	var release [1]byte
	if _, err := io.ReadFull(gate, release[:]); err != nil || release[0] != 'G' {
		return fmt.Errorf("supervisor release handshake was not received")
	}
	if err := errors.Join(ready.Close(), gate.Close(), specFile.Close()); err != nil {
		return err
	}
	return syscall.Exec(spec.Path, spec.Args, os.Environ()) // #nosec G204 -- Validated absolute command released only after supervisor membership and identity handshake.
}

func openCgroupRoot(root string) (int, error) {
	clean := filepath.Clean(root)
	filesystemRootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, fmt.Errorf("open filesystem root for cgroup resolution: %w", err)
	}
	defer unix.Close(filesystemRootFD)
	fd, err := unix.Openat2(filesystemRootFD, strings.TrimPrefix(clean, string(filepath.Separator)), &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, fmt.Errorf("securely open delegated cgroup root: %w", err)
	}
	if err := verifyCgroupV2FD(fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	controllersFD, err := unix.Openat(fd, "cgroup.controllers", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("configured root is not a delegated cgroup-v2 subtree: %w", err)
	}
	_ = unix.Close(controllersFD)
	return fd, nil
}

func verifyCgroupV2FD(fd int) error {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(fd, &stat); err != nil {
		return fmt.Errorf("inspect cgroup filesystem: %w", err)
	}
	if stat.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("configured boundary root is not cgroup v2")
	}
	return nil
}

func openExistingBoundary(root, boundaryID string) (int, string, error) {
	if _, err := resolveBoundaryPath(root, boundaryID); err != nil {
		return -1, "", err
	}
	rootFD, err := openCgroupRoot(root)
	if err != nil {
		return -1, "", err
	}
	defer unix.Close(rootFD)
	boundaryFD, err := unix.Openat(
		rootFD,
		boundaryID,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, "", fmt.Errorf("open existing cgroup boundary: %w", err)
	}
	if err := verifyCgroupV2FD(boundaryFD); err != nil {
		_ = unix.Close(boundaryFD)
		return -1, "", err
	}
	identity, err := nativeIdentityFromFD(boundaryFD)
	if err != nil {
		_ = unix.Close(boundaryFD)
		return -1, "", err
	}
	return boundaryFD, identity, nil
}

func nativeIdentityFromFD(fd int) (string, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return "", fmt.Errorf("read cgroup identity: %w", err)
	}
	return fmt.Sprintf("cgroupv2:%d:%d", uint64(stat.Dev), stat.Ino), nil
}

func verifyPIDInBoundaryFD(boundaryFD, expectedPID int) error {
	procsFD, err := unix.Openat(
		boundaryFD,
		"cgroup.procs",
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("read kernel cgroup membership: %w", err)
	}
	file := os.NewFile(uintptr(procsFD), "cgroup.procs")
	if file == nil {
		_ = unix.Close(procsFD)
		return fmt.Errorf("read kernel cgroup membership")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 128<<10))
	if err != nil {
		return fmt.Errorf("read kernel cgroup membership: %w", err)
	}
	pids, err := parsePIDList(raw)
	if err != nil {
		return err
	}
	if len(pids) != 1 || pids[0] != expectedPID {
		return fmt.Errorf(
			"%w: expected only PID %d in cgroup.procs",
			ErrMembershipMismatch,
			expectedPID,
		)
	}
	return nil
}

func validatedCommand(path string, arguments []string) (string, []string, error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return "", nil, fmt.Errorf("command path is required")
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve supervised command: %w", err)
	}
	if !filepath.IsAbs(resolved) {
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return "", nil, err
		}
	}
	if len(arguments) > 4096 {
		return "", nil, fmt.Errorf("command has too many arguments")
	}
	args := make([]string, 1, len(arguments)+1)
	args[0] = resolved
	for _, argument := range arguments {
		if len(argument) > 128<<10 || strings.IndexByte(argument, 0) >= 0 {
			return "", nil, fmt.Errorf("command argument exceeds safe bounds")
		}
		args = append(args, argument)
	}
	return resolved, args, nil
}

func waitForReady(ctx context.Context, reader io.Reader, timeout time.Duration) (string, error) {
	type result struct {
		line string
		err  error
	}
	resultChannel := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(reader, 512)).ReadString('\n')
		resultChannel <- result{line: line, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timer.C:
		return "", fmt.Errorf("handshake timed out")
	case result := <-resultChannel:
		if result.err != nil {
			return "", result.err
		}
		return result.line, nil
	}
}

func identityForPID(identities []ProcessIdentity, pid int) (ProcessIdentity, bool) {
	for _, identity := range identities {
		if identity.PID == pid {
			return identity, true
		}
	}
	return ProcessIdentity{}, false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func closeChildPipeEnds(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func abortProcess(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Kill()
	_ = command.Wait()
}

func IsChildMode(arguments []string) bool {
	return len(arguments) == 1 && arguments[0] == childModeArgument
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return 1
}
