// Package linuxsupervisor contains the minimal Linux-only execution boundary
// used to start an explicitly supervised process. The portable pieces in this
// file intentionally describe coverage without claiming eBPF support.
package linuxsupervisor

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	ErrUnsupported        = errors.New("linux cgroup-v2 supervision is unsupported on this platform")
	ErrInvalidBoundary    = errors.New("invalid execution boundary")
	ErrMembershipMismatch = errors.New("process membership does not match the execution boundary")
	ErrCoverageIncomplete = errors.New("process membership coverage is incomplete")
)

const (
	maxBoundaryIDBytes = 64
	maxLaunchSpecBytes = 512 << 10
)

var boundaryIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// Config identifies a delegated cgroup-v2 subtree and the procfs mounted for
// the same host. HelperPath must be this package's small supervisor command,
// not an agent executable.
type Config struct {
	CgroupRoot       string
	ProcRoot         string
	MachineID        string
	HelperPath       string
	HandshakeTimeout time.Duration
}

// Boundary is an opaque execution boundary. Path is deliberately private so
// callers cannot accidentally persist or display a raw cgroup path.
type Boundary struct {
	ID             string
	NativeIdentity string
	PathDigest     string

	//lint:ignore U1000 root is a Linux-only ownership guard used by launcher_linux.go.
	root string
	path string
	fd   int
}

// ProcessIdentity is a process-lifetime identity. PID remains display-only;
// StableKey includes the host boot and process start identity.
type ProcessIdentity struct {
	StableKey      string
	PID            int
	BootID         string
	StartTicks     string
	BoundaryID     string
	NativeIdentity string
}

// CoverageState is deliberately narrower than an eBPF coverage report. This
// package observes cgroup membership through cgroupfs and procfs only.
type CoverageState struct {
	ObservationMode     string
	Available           bool
	PermissionValid     bool
	Complete            bool
	MembershipVerified  bool
	EBPFAvailable       bool
	DroppedObservations uint64
	Members             []ProcessIdentity
	MissingPIDs         []int
	Reason              string
}

// VerifiedForLaunch reports whether this membership snapshot is sufficient to
// release the pre-exec helper. It does not activate a control-plane managed
// session; workload-identity binding is a separate required step.
func (c CoverageState) VerifiedForLaunch() bool {
	return c.Available && c.PermissionValid && c.Complete &&
		c.MembershipVerified && c.DroppedObservations == 0 && len(c.Members) > 0
}

// LaunchSpec contains the explicit command approved by the local operator.
// Arguments are carried over a private pipe to keep them out of the temporary
// helper's process listing before exec.
type LaunchSpec struct {
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// LaunchedProcess is returned only after the helper and parent independently
// verified cgroup membership and the stable process identity. BoundaryVerified
// is not a claim that the control-plane session is already managed.
type LaunchedProcess struct {
	Command          *exec.Cmd
	Identity         ProcessIdentity
	Coverage         CoverageState
	Boundary         *Boundary
	BoundaryVerified bool
}

func validateBoundaryID(value string) error {
	if len(value) == 0 || len(value) > maxBoundaryIDBytes ||
		!boundaryIDPattern.MatchString(value) || strings.Contains(value, "..") {
		return fmt.Errorf("%w: boundary ID must be one safe path component", ErrInvalidBoundary)
	}
	return nil
}
