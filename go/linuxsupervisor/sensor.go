package linuxsupervisor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/phigonai/observer/go/supervision"
)

const maxObservedMembers = 4096

type readFileSystem interface {
	ReadFile(string) ([]byte, error)
}

type osReadFileSystem struct{}

func (osReadFileSystem) ReadFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fs.ErrInvalid
	}
	// #nosec G304 -- production callers pass only paths returned by
	// resolveBoundaryPath or resolveProcPath, both of which enforce a configured
	// absolute root and reject traversal components. The interface exists only
	// to substitute an in-memory reader in sensor tests.
	return os.ReadFile(path)
}

// SensorConfig describes an observe-only cgroupfs/procfs membership sensor.
type SensorConfig struct {
	CgroupRoot string
	ProcRoot   string
	MachineID  string
}

// MembershipSensor polls cgroupfs and procfs. It does not load kernel code and
// must never be presented as eBPF coverage.
type MembershipSensor struct {
	config  SensorConfig
	files   readFileSystem
	dropped atomic.Uint64
}

func NewMembershipSensor(config SensorConfig) (*MembershipSensor, error) {
	return newMembershipSensor(config, osReadFileSystem{})
}

func newMembershipSensor(config SensorConfig, files readFileSystem) (*MembershipSensor, error) {
	if strings.TrimSpace(config.MachineID) == "" {
		return nil, fmt.Errorf("machine identity is required")
	}
	if _, err := resolveBoundaryPath(config.CgroupRoot, "validation"); err != nil {
		return nil, err
	}
	if _, err := resolveProcPath(config.ProcRoot, "self", "stat"); err != nil {
		return nil, err
	}
	if files == nil {
		return nil, fmt.Errorf("filesystem reader is required")
	}
	return &MembershipSensor{config: config, files: files}, nil
}

// RecordDropped marks known sensor loss. Coverage stays degraded for the
// lifetime of this sensor so a positive label cannot hide an earlier gap.
func (s *MembershipSensor) RecordDropped(count uint64) {
	if count == 0 {
		return
	}
	s.dropped.Add(count)
}

// Observe verifies the exact boundary membership and derives process-lifetime
// keys for every visible member. expectedPIDs should contain the root process
// for an active managed session.
func (s *MembershipSensor) Observe(boundary *Boundary, expectedPIDs ...int) CoverageState {
	state := CoverageState{
		ObservationMode:     "cgroup_v2_procfs_membership",
		EBPFAvailable:       false,
		DroppedObservations: s.dropped.Load(),
	}
	if boundary == nil || validateBoundaryID(boundary.ID) != nil ||
		boundary.NativeIdentity == "" {
		state.Reason = "execution boundary is missing or invalid"
		return state
	}
	boundaryPath, err := resolveBoundaryPath(s.config.CgroupRoot, boundary.ID)
	if err != nil || (boundary.path != "" && boundary.path != boundaryPath) {
		state.Reason = "execution boundary escaped the configured root"
		return state
	}
	membershipPath, err := s.membershipPath(boundary, boundaryPath)
	if err != nil {
		state.Reason = "execution boundary membership descriptor is invalid"
		return state
	}
	membersRaw, err := s.files.ReadFile(membershipPath)
	if err != nil {
		state.PermissionValid = !errors.Is(err, fs.ErrPermission)
		state.Reason = boundedReadReason("cgroup membership", err)
		return state
	}
	state.Available = true
	state.PermissionValid = true
	members, err := parsePIDList(membersRaw)
	if err != nil {
		state.Reason = err.Error()
		return state
	}
	memberSet := make(map[int]struct{}, len(members))
	for _, pid := range members {
		memberSet[pid] = struct{}{}
	}
	for _, pid := range expectedPIDs {
		if pid < 1 {
			state.MissingPIDs = append(state.MissingPIDs, pid)
			continue
		}
		if _, ok := memberSet[pid]; !ok {
			state.MissingPIDs = append(state.MissingPIDs, pid)
		}
	}
	for _, pid := range members {
		identity, identityErr := s.readProcessIdentity(boundary, membershipPath, pid)
		if identityErr != nil {
			state.MissingPIDs = append(state.MissingPIDs, pid)
			continue
		}
		state.Members = append(state.Members, identity)
	}
	sort.Ints(state.MissingPIDs)
	state.MembershipVerified = len(state.Members) > 0 && len(state.MissingPIDs) == 0
	state.Complete = state.MembershipVerified && state.DroppedObservations == 0
	switch {
	case len(members) == 0:
		state.Reason = "boundary has no observable members"
	case len(state.MissingPIDs) > 0:
		state.Reason = "one or more expected members were missing or mismatched"
	case state.DroppedObservations > 0:
		state.Reason = "known membership observations were dropped"
	default:
		state.Reason = "cgroup membership and stable process identities verified"
	}
	return state
}

func (s *MembershipSensor) membershipPath(boundary *Boundary, boundaryPath string) (string, error) {
	if boundary.fd < 0 {
		return filepath.Join(boundaryPath, "cgroup.procs"), nil
	}
	return resolveProcPath(
		s.config.ProcRoot,
		"self", "fd", strconv.Itoa(boundary.fd), "cgroup.procs",
	)
}

func (s *MembershipSensor) readProcessIdentity(
	boundary *Boundary,
	membershipPath string,
	pid int,
) (ProcessIdentity, error) {
	if pid < 1 {
		return ProcessIdentity{}, fmt.Errorf("process ID must be positive")
	}
	pidComponent := strconv.Itoa(pid)
	bootPath, err := resolveProcPath(s.config.ProcRoot, "sys", "kernel", "random", "boot_id")
	if err != nil {
		return ProcessIdentity{}, err
	}
	statPath, err := resolveProcPath(s.config.ProcRoot, pidComponent, "stat")
	if err != nil {
		return ProcessIdentity{}, err
	}
	cgroupPath, err := resolveProcPath(s.config.ProcRoot, pidComponent, "cgroup")
	if err != nil {
		return ProcessIdentity{}, err
	}
	bootRaw, err := s.files.ReadFile(bootPath)
	if err != nil {
		return ProcessIdentity{}, err
	}
	statRaw, err := s.files.ReadFile(statPath)
	if err != nil {
		return ProcessIdentity{}, err
	}
	cgroupRaw, err := s.files.ReadFile(cgroupPath)
	if err != nil {
		return ProcessIdentity{}, err
	}
	bootID := strings.TrimSpace(string(bootRaw))
	startTicks, err := parseProcStartTicks(statRaw, pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	if !hasUnifiedCgroupEntry(cgroupRaw) {
		return ProcessIdentity{}, ErrMembershipMismatch
	}
	// Re-read the original boundary's cgroup.procs after collecting procfs
	// identity. For production boundaries this path is anchored to the open
	// directory descriptor, so a same-named cgroup elsewhere cannot pass.
	membersRaw, err := s.files.ReadFile(membershipPath)
	if err != nil {
		return ProcessIdentity{}, err
	}
	members, err := parsePIDList(membersRaw)
	if err != nil {
		return ProcessIdentity{}, err
	}
	if !containsPID(members, pid) {
		return ProcessIdentity{}, ErrMembershipMismatch
	}
	stableKey, err := supervision.StableProcessKey(supervision.ProcessKeyMaterial{
		MachineID:     s.config.MachineID,
		BootID:        bootID,
		ProcessID:     uint64(pid),
		StartIdentity: startTicks,
	})
	if err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{
		StableKey:      stableKey,
		PID:            pid,
		BootID:         bootID,
		StartTicks:     startTicks,
		BoundaryID:     boundary.ID,
		NativeIdentity: boundary.NativeIdentity,
	}, nil
}

func parsePIDList(raw []byte) ([]int, error) {
	fields := strings.Fields(string(raw))
	if len(fields) > maxObservedMembers {
		return nil, fmt.Errorf("cgroup membership exceeds %d processes", maxObservedMembers)
	}
	unique := make(map[int]struct{}, len(fields))
	for _, field := range fields {
		pid, err := strconv.Atoi(field)
		if err != nil || pid < 1 {
			return nil, fmt.Errorf("cgroup membership contains an invalid PID")
		}
		unique[pid] = struct{}{}
	}
	result := make([]int, 0, len(unique))
	for pid := range unique {
		result = append(result, pid)
	}
	sort.Ints(result)
	return result, nil
}

func parseProcStartTicks(raw []byte, expectedPID int) (string, error) {
	line := strings.TrimSpace(string(raw))
	closing := strings.LastIndex(line, ")")
	opening := strings.Index(line, "(")
	if opening < 1 || closing <= opening {
		return "", fmt.Errorf("process stat is malformed")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line[:opening]))
	if err != nil || pid != expectedPID {
		return "", fmt.Errorf("process stat PID does not match membership")
	}
	// The first token after comm is field 3 (state); starttime is field 22.
	fields := strings.Fields(line[closing+1:])
	if len(fields) <= 19 || !decimalDigits(fields[19]) {
		return "", fmt.Errorf("process stat start identity is missing")
	}
	return fields[19], nil
}

func hasUnifiedCgroupEntry(raw []byte) bool {
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		if filepath.IsAbs(parts[2]) {
			return true
		}
	}
	return false
}

func containsPID(members []int, expected int) bool {
	index := sort.SearchInts(members, expected)
	return index < len(members) && members[index] == expected
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func boundedReadReason(label string, err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return label + " permission was denied"
	case errors.Is(err, fs.ErrNotExist):
		return label + " is unavailable"
	default:
		return label + " could not be read"
	}
}
