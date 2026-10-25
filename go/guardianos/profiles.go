// Package guardianos contains administrator-owned OS restrictions. Profiles
// are delivered by the authenticated server and are bound into launch grants.
package guardianos

import (
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/google/uuid"
)

type Profile struct {
	Name          string        `json:"name"`
	Platform      string        `json:"platform"`
	ReadPaths     []string      `json:"read_paths"`
	WritePaths    []string      `json:"write_paths"`
	ExecutePaths  []string      `json:"execute_paths"`
	Network       string        `json:"network"`
	RequireCgroup bool          `json:"require_cgroup"`
	Limits        *Limits       `json:"limits,omitempty"`
	RunAs         *UnixIdentity `json:"run_as,omitempty"`
}
type Assignment struct {
	TenantID  string  `json:"tenant_id"`
	MachineID string  `json:"machine_id,omitempty"`
	Profile   Profile `json:"profile"`
}
type Catalog struct{ assignments []Assignment }

func decode(raw string, target any) error {
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing OS profile data")
	}
	return nil
}
func Validate(p Profile) error {
	if len(p.Name) == 0 || len(p.Name) > 128 || strings.ContainsAny(p.Name, "\x00\r\n") || (p.Platform != "linux" && p.Platform != "windows" && p.Platform != "darwin") || (p.Network != "deny" && p.Network != "inherit") {
		return errors.New("OS profile requires a name, supported platform and explicit network mode")
	}
	if p.Limits != nil {
		if err := p.Limits.Validate(); err != nil {
			return err
		}
	}
	if p.RunAs != nil && (p.Platform != "linux" || p.RunAs.UID == 0 || p.RunAs.GID == 0 || p.RunAs.UID == ^uint32(0) || p.RunAs.GID == ^uint32(0)) {
		return errors.New("workload identity requires a non-root Linux UID and GID")
	}
	if p.Platform != "linux" {
		if len(p.ReadPaths)+len(p.WritePaths)+len(p.ExecutePaths) != 0 || p.Network != "inherit" || p.RequireCgroup || p.Limits == nil {
			return errors.New("this platform supports only explicit resource-limit profiles")
		}
		if p.Platform == "darwin" && p.Limits.HasKernelLimits() {
			return errors.New("macOS currently supports runtime limits only; aggregate kernel resource limits are unavailable")
		}
		return nil
	}
	if len(p.ReadPaths) > 64 || len(p.WritePaths) > 64 || len(p.ExecutePaths) == 0 || len(p.ExecutePaths) > 64 {
		return errors.New("OS profile path limits exceeded")
	}
	for _, paths := range [][]string{p.ReadPaths, p.WritePaths, p.ExecutePaths} {
		seen := map[string]bool{}
		for _, v := range paths {
			if len(v) > 4096 || !path.IsAbs(v) || path.Clean(v) != v || strings.ContainsAny(v, "\x00\r\n") || seen[v] {
				return errors.New("OS profile requires unique, normalized absolute paths")
			}
			seen[v] = true
		}
	}
	for _, v := range p.WritePaths {
		for _, reserved := range []string{"/", "/proc", "/sys", "/dev"} {
			if v == reserved || reserved != "/" && strings.HasPrefix(v, reserved+"/") {
				return errors.New("OS profile cannot grant writes to kernel or device control paths")
			}
		}
	}
	return nil
}
func New(raw string) (*Catalog, error) {
	c := &Catalog{}
	if strings.TrimSpace(raw) == "" {
		return c, nil
	}
	if len(raw) > 1<<20 || decode(raw, &c.assignments) != nil || len(c.assignments) > 256 {
		return nil, errors.New("invalid OS profile assignments")
	}
	scoped := map[string]map[string][]Profile{}
	for i := range c.assignments {
		a := &c.assignments[i]
		tenant, err := uuid.Parse(a.TenantID)
		if err != nil || tenant == uuid.Nil {
			return nil, errors.New("invalid OS profile tenant")
		}
		a.TenantID = tenant.String()
		if a.MachineID != "" {
			machine, err := uuid.Parse(a.MachineID)
			if err != nil || machine == uuid.Nil {
				return nil, errors.New("invalid OS profile machine")
			}
			a.MachineID = machine.String()
		}
		if err := Validate(a.Profile); err != nil {
			return nil, err
		}
		if scoped[a.TenantID] == nil {
			scoped[a.TenantID] = map[string][]Profile{}
		}
		scoped[a.TenantID][a.MachineID] = append(scoped[a.TenantID][a.MachineID], a.Profile)
	}
	// Bounds apply to the effective stack on one machine. Independent machine
	// assignments do not consume each other's profile or payload budgets.
	for _, machines := range scoped {
		for machineID, machineProfiles := range machines {
			platforms := []string{"linux", "windows", "darwin"}
			if machineID != "" {
				platforms = []string{machineProfiles[0].Platform}
			}
			for _, platform := range platforms {
				profiles := []Profile{}
				for _, profile := range machines[""] {
					if profile.Platform == platform {
						profiles = append(profiles, profile)
					}
				}
				if machineID != "" {
					profiles = append(profiles, machineProfiles...)
				}
				if len(profiles) > 8 {
					return nil, errors.New("a machine may receive at most eight stacked OS profiles")
				}
				if _, err := ConstraintsFor(profiles); err != nil {
					return nil, err
				}
				encoded, _ := json.Marshal(profiles)
				if len(encoded) > 24<<10 {
					return nil, errors.New("effective OS profile payload exceeds 24 KiB")
				}
			}
		}
	}
	return c, nil
}

// Matching fleet and machine profiles are stacked. A machine exception cannot
// broaden the kernel rights allowed by a fleet profile.
func (c *Catalog) Effective(tenant, machine, platform string) string {
	if platform == "macos" {
		platform = "darwin"
	}
	profiles := []Profile{}
	if c != nil {
		for _, a := range c.assignments {
			// Machine-specific assignments are never silently discarded on a
			// platform mismatch: the native/server validation must refuse launch.
			if a.TenantID == tenant && (a.MachineID == "" && a.Profile.Platform == platform || a.MachineID != "" && a.MachineID == machine) {
				profiles = append(profiles, a.Profile)
			}
		}
	}
	if len(profiles) == 0 {
		return ""
	}
	data, _ := json.Marshal(profiles)
	return string(data)
}
func Parse(raw string) ([]Profile, error) {
	var profiles []Profile
	if raw == "" {
		return profiles, nil
	}
	if len(raw) > 24<<10 || decode(raw, &profiles) != nil || len(profiles) == 0 || len(profiles) > 8 {
		return nil, errors.New("invalid execution OS profiles")
	}
	for _, p := range profiles {
		if err := Validate(p); err != nil {
			return nil, err
		}
	}
	if _, err := ConstraintsFor(profiles); err != nil {
		return nil, err
	}
	return profiles, nil
}
