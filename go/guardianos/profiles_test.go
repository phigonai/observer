package guardianos

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAssignmentsStackWithoutCrossTenantOrMachineLeakage(t *testing.T) {
	tenant := "00000000-0000-4000-8000-000000000001"
	machine := "00000000-0000-4000-8000-000000000002"
	base := Profile{Name: "Company", Platform: "linux", ReadPaths: []string{"/usr"}, ExecutePaths: []string{"/usr/bin/python3"}, Network: "deny"}
	extra := base
	extra.Name = "Specific machine"
	extra.ReadPaths = []string{"/srv/project"}
	raw, _ := json.Marshal([]Assignment{{TenantID: tenant, Profile: base}, {TenantID: tenant, MachineID: machine, Profile: extra}})
	catalog, err := New(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := Parse(catalog.Effective(tenant, machine, "linux"))
	if err != nil || len(profiles) != 2 {
		t.Fatalf("profiles=%v err=%v", profiles, err)
	}
	profiles, _ = Parse(catalog.Effective(tenant, "other", "linux"))
	if len(profiles) != 1 || profiles[0].Network != "deny" {
		t.Fatal("fleet restriction lost")
	}
	if catalog.Effective("another-company", machine, "linux") != "" {
		t.Fatal("tenant boundary crossed")
	}
	var empty *Catalog
	if empty.Effective(tenant, machine, "linux") != "" {
		t.Fatal("nil catalog must not invent restrictions")
	}
}

func TestProfileLimitsArePerEffectiveMachine(t *testing.T) {
	tenant := uuid.New().String()
	profile := Profile{Name: "Company", Platform: "linux", ExecutePaths: []string{"/usr/bin/python3"}, Network: "deny"}
	assignments := []Assignment{{TenantID: tenant, Profile: profile}}
	for range 20 {
		assignments = append(assignments, Assignment{TenantID: tenant, MachineID: uuid.New().String(), Profile: profile})
	}
	raw, _ := json.Marshal(assignments)
	catalog, err := New(string(raw))
	if err != nil {
		t.Fatal("independent machines exhausted each other's profile budget:", err)
	}
	profiles, err := Parse(catalog.Effective(tenant, assignments[1].MachineID, "linux"))
	if err != nil || len(profiles) != 2 {
		t.Fatalf("effective stack=%+v err=%v", profiles, err)
	}
	for range 7 {
		assignments = append(assignments, assignments[1])
	}
	raw, _ = json.Marshal(assignments)
	if _, err := New(string(raw)); err == nil {
		t.Fatal("nine profiles on a single machine accepted")
	}
}

func TestUnsafeAndUnsupportedProfilesAreRejected(t *testing.T) {
	base := Profile{Name: "Company", Platform: "linux", ExecutePaths: []string{"/usr/bin/python3"}, Network: "deny"}
	for _, value := range []string{"/", "/proc", "/proc/self", "/sys/fs/cgroup", "/dev/mem", "/tmp/../etc", "relative", "/tmp\nfoo"} {
		profile := base
		profile.WritePaths = []string{value}
		if Validate(profile) == nil {
			t.Errorf("unsafe writable path accepted: %q", value)
		}
	}
	profile := base
	profile.Platform = "windows"
	if Validate(profile) == nil {
		t.Fatal("unsupported OS claims accepted")
	}
	profile = base
	profile.Network = "guess"
	if Validate(profile) == nil {
		t.Fatal("implicit network mode accepted")
	}
	for _, raw := range []string{`[]`, `[{"unknown":true}]`, strings.Repeat(" ", 25<<10)} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("invalid profiles accepted: %q", raw[:min(len(raw), 40)])
		}
	}
}
