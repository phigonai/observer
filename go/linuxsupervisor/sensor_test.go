//go:build linux

package linuxsupervisor

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type fakeReadFileSystem struct {
	values    map[string][]byte
	errors    map[string]error
	sequences map[string][][]byte
	reads     map[string]int
}

func (f *fakeReadFileSystem) ReadFile(path string) ([]byte, error) {
	if err := f.errors[path]; err != nil {
		return nil, err
	}
	if sequence, ok := f.sequences[path]; ok && len(sequence) > 0 {
		index := f.reads[path]
		f.reads[path] = index + 1
		if index >= len(sequence) {
			index = len(sequence) - 1
		}
		return append([]byte(nil), sequence[index]...), nil
	}
	value, ok := f.values[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}

func TestResolveBoundaryPathRejectsTraversal(t *testing.T) {
	t.Parallel()
	for _, boundaryID := range []string{"", "..", "../agent", "agent/child", `agent\\child`, ".hidden"} {
		if _, err := resolveBoundaryPath("/delegated/phigon", boundaryID); err == nil {
			t.Fatalf("resolveBoundaryPath accepted %q", boundaryID)
		}
	}
	if _, err := resolveBoundaryPath("relative", "agent-a"); err == nil {
		t.Fatal("resolveBoundaryPath accepted a relative root")
	}
	path, err := resolveBoundaryPath("/delegated/phigon", "agent-a_1")
	if err != nil || path != filepath.Join("/delegated/phigon", "agent-a_1") {
		t.Fatalf("resolveBoundaryPath = %q, %v", path, err)
	}
}

func TestMembershipMismatchDegradesCoverage(t *testing.T) {
	t.Parallel()
	files, boundary := healthyFixture(42, "1000")
	files.values["/proc/42/cgroup"] = []byte("0::/phigon/other-boundary\n")
	files.sequences["/delegated/boundary-a/cgroup.procs"] = [][]byte{
		[]byte("42\n"),
		nil,
	}
	sensor := newTestSensor(t, files)

	coverage := sensor.Observe(boundary, 42)
	if !coverage.Available || !coverage.PermissionValid {
		t.Fatalf("expected readable sensor, got %#v", coverage)
	}
	if coverage.Complete || coverage.MembershipVerified || coverage.VerifiedForLaunch() {
		t.Fatalf("mismatched membership was treated as complete: %#v", coverage)
	}
	if len(coverage.MissingPIDs) != 1 || coverage.MissingPIDs[0] != 42 {
		t.Fatalf("missing PIDs = %#v", coverage.MissingPIDs)
	}
}

func TestSameBasenameInDifferentHierarchyCannotVerifyMembership(t *testing.T) {
	t.Parallel()
	files, boundary := healthyFixture(42, "1000")
	files.values["/proc/42/cgroup"] = []byte("0::/unrelated/boundary-a\n")
	files.sequences["/delegated/boundary-a/cgroup.procs"] = [][]byte{
		[]byte("42\n"),
		nil,
	}
	sensor := newTestSensor(t, files)

	coverage := sensor.Observe(boundary, 42)
	if coverage.MembershipVerified || coverage.VerifiedForLaunch() {
		t.Fatalf("same basename in another hierarchy verified: %#v", coverage)
	}
}

func TestMembershipRechecksTheOpenBoundaryDescriptor(t *testing.T) {
	t.Parallel()
	files, boundary := healthyFixture(42, "1000")
	boundary.fd = 7
	delete(files.values, "/delegated/boundary-a/cgroup.procs")
	files.values["/proc/self/fd/7/cgroup.procs"] = []byte("42\n")
	sensor := newTestSensor(t, files)

	coverage := sensor.Observe(boundary, 42)
	if !coverage.VerifiedForLaunch() {
		t.Fatalf("descriptor-anchored membership did not verify: %#v", coverage)
	}
}

func TestExpectedMemberAbsentDegradesCoverage(t *testing.T) {
	t.Parallel()
	files, boundary := healthyFixture(42, "1000")
	files.values["/delegated/boundary-a/cgroup.procs"] = nil
	sensor := newTestSensor(t, files)

	coverage := sensor.Observe(boundary, 42)
	if !coverage.Available || coverage.Complete || coverage.VerifiedForLaunch() {
		t.Fatalf("missing expected member was not fail-closed: %#v", coverage)
	}
	if len(coverage.MissingPIDs) != 1 || coverage.MissingPIDs[0] != 42 {
		t.Fatalf("missing PIDs = %#v", coverage.MissingPIDs)
	}
}

func TestPIDReuseProducesDifferentStableProcessKey(t *testing.T) {
	t.Parallel()
	files, boundary := healthyFixture(42, "1000")
	sensor := newTestSensor(t, files)
	first := sensor.Observe(boundary, 42)
	if !first.VerifiedForLaunch() {
		t.Fatalf("first coverage = %#v", first)
	}

	files.values["/proc/42/stat"] = procStat(42, "2000")
	second := sensor.Observe(boundary, 42)
	if !second.VerifiedForLaunch() {
		t.Fatalf("second coverage = %#v", second)
	}
	if first.Members[0].StableKey == second.Members[0].StableKey {
		t.Fatal("PID reuse retained the prior process-lifetime key")
	}
}

func TestMissingAndDroppedCoverageFailClosed(t *testing.T) {
	t.Parallel()
	files, boundary := healthyFixture(42, "1000")
	membershipPath := "/delegated/boundary-a/cgroup.procs"
	delete(files.values, membershipPath)
	files.errors[membershipPath] = fs.ErrPermission
	sensor := newTestSensor(t, files)

	missing := sensor.Observe(boundary, 42)
	if missing.Available || missing.PermissionValid || missing.Complete || missing.VerifiedForLaunch() {
		t.Fatalf("permission loss was not fail-closed: %#v", missing)
	}

	delete(files.errors, membershipPath)
	files.values[membershipPath] = []byte("42\n")
	sensor.RecordDropped(2)
	dropped := sensor.Observe(boundary, 42)
	if !dropped.Available || !dropped.PermissionValid || dropped.Complete || dropped.VerifiedForLaunch() {
		t.Fatalf("known drops were not surfaced: %#v", dropped)
	}
	if dropped.DroppedObservations != 2 || dropped.EBPFAvailable {
		t.Fatalf("drop/eBPF state = %#v", dropped)
	}
}

func TestLifecycleCannotSkipVerifiedMembership(t *testing.T) {
	t.Parallel()
	lifecycle := NewLifecycle()
	boundary := &Boundary{ID: "boundary-a", NativeIdentity: "cgroupv2:1:2"}
	if err := lifecycle.LaunchVerified("process-key"); err == nil {
		t.Fatal("lifecycle became managed before boundary creation")
	}
	if err := lifecycle.BoundaryReady(boundary); err != nil {
		t.Fatalf("BoundaryReady: %v", err)
	}
	if err := lifecycle.MembershipVerified(CoverageState{
		Reason: "sensor unavailable",
	}); !errors.Is(err, ErrCoverageIncomplete) {
		t.Fatalf("incomplete membership error = %v", err)
	}
	coverage := CoverageState{
		ObservationMode:    "cgroup_v2_procfs_membership",
		Available:          true,
		PermissionValid:    true,
		Complete:           true,
		MembershipVerified: true,
		Members: []ProcessIdentity{{
			StableKey: "process-key",
			PID:       42,
		}},
	}
	if err := lifecycle.MembershipVerified(coverage); err != nil {
		t.Fatalf("MembershipVerified: %v", err)
	}
	if err := lifecycle.LaunchVerified("other-key"); err == nil {
		t.Fatal("lifecycle accepted a different process identity")
	}
	if err := lifecycle.LaunchVerified("process-key"); err != nil {
		t.Fatalf("LaunchVerified: %v", err)
	}
	state, _ := lifecycle.State()
	if state != LifecycleLaunchVerified {
		t.Fatalf("state = %q", state)
	}
	lifecycle.Close()
	state, _ = lifecycle.State()
	if state != LifecycleClosed {
		t.Fatalf("closed state = %q", state)
	}
}

func TestProcStatParserHandlesSpacesAndClosingParenthesis(t *testing.T) {
	t.Parallel()
	start, err := parseProcStartTicks(procStatNamed(42, "agent (worker)", "12345"), 42)
	if err != nil || start != "12345" {
		t.Fatalf("parseProcStartTicks = %q, %v", start, err)
	}
	if _, err := parseProcStartTicks(procStat(43, "12345"), 42); err == nil {
		t.Fatal("parser accepted a mismatched PID")
	}
}

func newTestSensor(t *testing.T, files *fakeReadFileSystem) *MembershipSensor {
	t.Helper()
	sensor, err := newMembershipSensor(SensorConfig{
		CgroupRoot: "/delegated",
		ProcRoot:   "/proc",
		MachineID:  "machine-a",
	}, files)
	if err != nil {
		t.Fatalf("newMembershipSensor: %v", err)
	}
	return sensor
}

func healthyFixture(pid int, startTicks string) (*fakeReadFileSystem, *Boundary) {
	pidText := strconv.Itoa(pid)
	return &fakeReadFileSystem{
			values: map[string][]byte{
				"/delegated/boundary-a/cgroup.procs": []byte(pidText + "\n"),
				"/proc/sys/kernel/random/boot_id":    []byte("boot-a\n"),
				"/proc/" + pidText + "/stat":         procStat(pid, startTicks),
				"/proc/" + pidText + "/cgroup":       []byte("0::/phigon/boundary-a\n"),
			},
			errors:    make(map[string]error),
			sequences: make(map[string][][]byte),
			reads:     make(map[string]int),
		}, &Boundary{
			ID:             "boundary-a",
			NativeIdentity: "cgroupv2:1:2",
			root:           "/delegated",
			path:           "/delegated/boundary-a",
			fd:             -1,
		}
}

func procStat(pid int, startTicks string) []byte {
	return procStatNamed(pid, "agent worker", startTicks)
}

func procStatNamed(pid int, name, startTicks string) []byte {
	fields := make([]string, 20)
	fields[0] = "S"
	for index := 1; index < 19; index++ {
		fields[index] = "0"
	}
	fields[19] = startTicks
	return []byte(strconv.Itoa(pid) + " (" + name + ") " + strings.Join(fields, " ") + "\n")
}
