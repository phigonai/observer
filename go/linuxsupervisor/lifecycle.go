package linuxsupervisor

import (
	"fmt"
	"sync"
)

type LifecycleState string

const (
	LifecycleCreating           LifecycleState = "creating"
	LifecycleBoundaryReady      LifecycleState = "boundary_ready"
	LifecycleMembershipVerified LifecycleState = "membership_verified"
	LifecycleLaunchVerified     LifecycleState = "launch_verified"
	LifecycleDegraded           LifecycleState = "degraded"
	LifecycleClosed             LifecycleState = "closed"
)

// Lifecycle is a local fail-closed state machine. The control plane remains
// authoritative, but callers cannot accidentally report managed before this
// package has verified a stable member inside the created boundary.
type Lifecycle struct {
	mu      sync.Mutex
	state   LifecycleState
	reason  string
	process string
}

func NewLifecycle() *Lifecycle {
	return &Lifecycle{state: LifecycleCreating}
}

func (l *Lifecycle) State() (LifecycleState, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state, l.reason
}

func (l *Lifecycle) BoundaryReady(boundary *Boundary) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != LifecycleCreating || boundary == nil ||
		validateBoundaryID(boundary.ID) != nil || boundary.NativeIdentity == "" {
		return fmt.Errorf("%w: boundary is not ready", ErrInvalidBoundary)
	}
	l.state = LifecycleBoundaryReady
	l.reason = ""
	return nil
}

func (l *Lifecycle) MembershipVerified(coverage CoverageState) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != LifecycleBoundaryReady || !coverage.VerifiedForLaunch() ||
		len(coverage.Members) == 0 || coverage.Members[0].StableKey == "" {
		return fmt.Errorf("%w: %s", ErrCoverageIncomplete, coverage.Reason)
	}
	l.process = coverage.Members[0].StableKey
	l.state = LifecycleMembershipVerified
	l.reason = ""
	return nil
}

func (l *Lifecycle) LaunchVerified(processKey string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != LifecycleMembershipVerified || processKey == "" ||
		processKey != l.process {
		return fmt.Errorf("%w: stable process identity was not verified", ErrCoverageIncomplete)
	}
	l.state = LifecycleLaunchVerified
	l.reason = ""
	return nil
}

func (l *Lifecycle) Degrade(reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == LifecycleClosed {
		return
	}
	l.state = LifecycleDegraded
	if reason == "" {
		reason = "coverage became incomplete"
	}
	l.reason = reason
}

func (l *Lifecycle) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state = LifecycleClosed
	l.reason = ""
}
