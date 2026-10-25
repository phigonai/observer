package guardianos

import "errors"

type Limits struct {
	MaxMemoryBytes    int64 `json:"max_memory_bytes,omitempty"`
	MaxProcesses      int   `json:"max_processes,omitempty"`
	MaxCPUPercent     int   `json:"max_cpu_percent,omitempty"`
	MaxRuntimeSeconds int   `json:"max_runtime_seconds,omitempty"`
}

type UnixIdentity struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type Constraints struct {
	Platform      string
	Limits        Limits
	RunAs         *UnixIdentity
	RequireCgroup bool
}

func (l Limits) HasKernelLimits() bool {
	return l.MaxMemoryBytes != 0 || l.MaxProcesses != 0 || l.MaxCPUPercent != 0
}

func (l Limits) Validate() error {
	if l.MaxMemoryBytes != 0 && (l.MaxMemoryBytes < 16<<20 || l.MaxMemoryBytes > 1<<50) || l.MaxProcesses < 0 || l.MaxProcesses > 65535 || l.MaxCPUPercent < 0 || l.MaxCPUPercent > 100 || l.MaxRuntimeSeconds < 0 || l.MaxRuntimeSeconds > 7*24*60*60 {
		return errors.New("invalid OS resource limits")
	}
	if l == (Limits{}) {
		return errors.New("resource limits must contain at least one nonzero restriction")
	}
	return nil
}

// A tighter machine limit always wins. Conflicting workload accounts or OS
// targets are invalid rather than selecting one administrator's instruction.
func ConstraintsFor(profiles []Profile) (Constraints, error) {
	var result Constraints
	for _, p := range profiles {
		if err := Validate(p); err != nil {
			return result, err
		}
		if result.Platform != "" && result.Platform != p.Platform {
			return result, errors.New("stacked OS profiles have incompatible platforms")
		}
		result.Platform = p.Platform
		result.RequireCgroup = result.RequireCgroup || p.RequireCgroup
		if p.RunAs != nil {
			if result.RunAs != nil && *result.RunAs != *p.RunAs {
				return result, errors.New("stacked OS profiles have conflicting workload identities")
			}
			identity := *p.RunAs
			result.RunAs = &identity
		}
		if p.Limits != nil {
			l := p.Limits
			result.Limits.MaxMemoryBytes = tighter(result.Limits.MaxMemoryBytes, l.MaxMemoryBytes)
			result.Limits.MaxProcesses = int(tighter(int64(result.Limits.MaxProcesses), int64(l.MaxProcesses)))
			result.Limits.MaxCPUPercent = int(tighter(int64(result.Limits.MaxCPUPercent), int64(l.MaxCPUPercent)))
			result.Limits.MaxRuntimeSeconds = int(tighter(int64(result.Limits.MaxRuntimeSeconds), int64(l.MaxRuntimeSeconds)))
		}
	}
	if result.Platform == "linux" && (result.Limits != (Limits{}) || result.RunAs != nil) {
		result.RequireCgroup = true
	}
	return result, nil
}

func tighter(a, b int64) int64 {
	if a == 0 {
		return b
	}
	if b == 0 || a < b {
		return a
	}
	return b
}
