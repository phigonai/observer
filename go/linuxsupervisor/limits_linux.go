//go:build linux

package linuxsupervisor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/phigonai/observer/go/guardianos"
	"golang.org/x/sys/unix"
)

// SetResourceLimits operates only on the newly created, descriptor-bound cgroup.
// Missing delegated controllers fail launch; this never reconfigures ancestors.
func (l *Launcher) SetResourceLimits(boundary *Boundary, limits guardianos.Limits) error {
	if boundary == nil || boundary.fd < 0 || boundary.root != filepath.Clean(l.config.CgroupRoot) {
		return ErrInvalidBoundary
	}
	if err := verifyCgroupV2FD(boundary.fd); err != nil {
		return err
	}
	if !limits.HasKernelLimits() {
		return nil
	}
	if err := limits.Validate(); err != nil {
		return err
	}
	settings := []struct {
		name  string
		value string
	}{}
	if limits.MaxProcesses > 0 {
		settings = append(settings, struct {
			name  string
			value string
		}{"pids.max", strconv.Itoa(limits.MaxProcesses)})
	}
	if limits.MaxMemoryBytes > 0 {
		// Round down to pages, never granting more memory than the admin allowed.
		memory := limits.MaxMemoryBytes / int64(os.Getpagesize()) * int64(os.Getpagesize())
		settings = append(settings, struct {
			name  string
			value string
		}{"memory.max", strconv.FormatInt(memory, 10)}, struct {
			name  string
			value string
		}{"memory.swap.max", "0"}, struct {
			name  string
			value string
		}{"memory.oom.group", "1"})
	}
	if limits.MaxCPUPercent > 0 {
		quota := int64(runtime.NumCPU()) * int64(limits.MaxCPUPercent) * 1000
		settings = append(settings, struct {
			name  string
			value string
		}{"cpu.max", fmt.Sprintf("%d 100000", quota)})
	}
	for _, setting := range settings {
		fd, err := unix.Openat(boundary.fd, setting.name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("required cgroup controller %s is unavailable: %w", setting.name, err)
		}
		file := os.NewFile(uintptr(fd), setting.name)
		n, err := file.WriteString(setting.value)
		if err != nil || n != len(setting.value) {
			_ = file.Close()
			return fmt.Errorf("could not install cgroup limit %s", setting.name)
		}
		if _, err := file.Seek(0, 0); err != nil {
			_ = file.Close()
			return err
		}
		value, err := io.ReadAll(io.LimitReader(file, 256))
		err = errors.Join(err, file.Close())
		if err != nil || strings.Join(strings.Fields(string(value)), " ") != setting.value {
			return fmt.Errorf("cgroup limit %s did not verify", setting.name)
		}
	}
	return nil
}
