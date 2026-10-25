package guardianos

import (
	"encoding/json"
	"testing"
)

func TestStackedLimitsCannotRelaxFleetRestrictions(t *testing.T) {
	base := Profile{Name: "Fleet", Platform: "linux", ExecutePaths: []string{"/usr/bin/python3"}, Network: "inherit", Limits: &Limits{MaxMemoryBytes: 128 << 20, MaxProcesses: 32, MaxCPUPercent: 20, MaxRuntimeSeconds: 60}, RunAs: &UnixIdentity{UID: 1001, GID: 1001}}
	local := base
	local.Limits = &Limits{MaxMemoryBytes: 256 << 20, MaxProcesses: 8, MaxCPUPercent: 50, MaxRuntimeSeconds: 30}
	for _, profiles := range [][]Profile{{base, local}, {local, base}} {
		got, err := ConstraintsFor(profiles)
		if err != nil || got.Limits != (Limits{MaxMemoryBytes: 128 << 20, MaxProcesses: 8, MaxCPUPercent: 20, MaxRuntimeSeconds: 30}) || !got.RequireCgroup || *got.RunAs != *base.RunAs {
			t.Fatalf("restrictions lost: %+v, %v", got, err)
		}
	}
	local.RunAs = &UnixIdentity{UID: 1002, GID: 1001}
	if _, err := ConstraintsFor([]Profile{base, local}); err == nil {
		t.Fatal("conflicting workload identities accepted")
	}
	base.Limits = nil
	got, err := ConstraintsFor([]Profile{base})
	if err != nil || !got.RequireCgroup {
		t.Fatal("separate identity must require cgroup containment")
	}
	base.RunAs = nil
	base.Limits = &Limits{MaxRuntimeSeconds: 2}
	got, err = ConstraintsFor([]Profile{base})
	if err != nil || !got.RequireCgroup {
		t.Fatal("runtime deadline must contain detached Linux descendants")
	}
}

func TestResourceLimitsRejectInvalidOrUnsupportedClaims(t *testing.T) {
	for _, limits := range []Limits{{}, {MaxMemoryBytes: 1}, {MaxMemoryBytes: 1<<50 + 1}, {MaxProcesses: -1}, {MaxProcesses: 65536}, {MaxCPUPercent: -1}, {MaxCPUPercent: 101}, {MaxRuntimeSeconds: -1}, {MaxRuntimeSeconds: 604801}} {
		if limits.Validate() == nil {
			t.Errorf("invalid limits accepted: %+v", limits)
		}
	}
	for _, platform := range []string{"windows", "darwin"} {
		p := Profile{Name: "Runtime", Platform: platform, Network: "inherit", Limits: &Limits{MaxRuntimeSeconds: 1}}
		if err := Validate(p); err != nil {
			t.Fatal(err)
		}
		p.Limits.MaxMemoryBytes = 16 << 20
		if (Validate(p) != nil) != (platform == "darwin") {
			t.Fatal("platform resource support misstated")
		}
		p.RunAs = &UnixIdentity{UID: 1001, GID: 1001}
		if Validate(p) == nil {
			t.Fatal("unsupported identity switching accepted")
		}
	}
	for _, identity := range []UnixIdentity{{}, {UID: 1001}, {GID: 1001}, {UID: ^uint32(0), GID: 1001}} {
		p := Profile{Name: "Identity", Platform: "linux", ExecutePaths: []string{"/usr/bin/python3"}, Network: "inherit", RunAs: &identity}
		if Validate(p) == nil {
			t.Fatalf("unsafe identity accepted: %+v", identity)
		}
	}
}

func TestMixedFleetProfilesSelectOSWithoutDroppingWrongMachineAssignment(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000001"
	const machine = "00000000-0000-4000-8000-000000000002"
	assignments := []Assignment{}
	for _, platform := range []string{"linux", "windows", "darwin"} {
		p := Profile{Name: platform, Platform: platform, Network: "inherit", Limits: &Limits{MaxRuntimeSeconds: 30}}
		if platform == "linux" {
			p.ExecutePaths = []string{"/usr/bin/python3"}
		}
		assignments = append(assignments, Assignment{TenantID: tenant, Profile: p})
	}
	data, _ := json.Marshal(assignments)
	catalog, err := New(string(data))
	if err != nil {
		t.Fatal(err)
	}
	for os, platform := range map[string]string{"linux": "linux", "windows": "windows", "macos": "darwin"} {
		profiles, err := Parse(catalog.Effective(tenant, machine, os))
		if err != nil || len(profiles) != 1 || profiles[0].Platform != platform {
			t.Fatalf("mixed fleet mismatch: %+v, %v", profiles, err)
		}
	}
	wrong := assignments[0]
	wrong.MachineID = machine
	assignments = append(assignments, wrong)
	data, _ = json.Marshal(assignments)
	catalog, err = New(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(catalog.Effective(tenant, machine, "windows")); err == nil {
		t.Fatal("wrong machine OS assignment was silently omitted")
	}
}
