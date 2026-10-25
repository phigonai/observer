//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/phigonai/observer/go/linuxsupervisor"
)

type launchStatus struct {
	Managed                        bool   `json:"managed"`
	BoundaryMembershipVerified     bool   `json:"boundary_membership_verified"`
	RequiresControlPlaneActivation bool   `json:"requires_control_plane_activation"`
	BoundaryID                     string `json:"boundary_id"`
	BoundaryIdentity               string `json:"boundary_identity"`
	ProcessKey                     string `json:"process_key"`
	ProcessID                      int    `json:"process_id"`
	CoverageMode                   string `json:"coverage_mode"`
	CoverageComplete               bool   `json:"coverage_complete"`
	EBPFAvailable                  bool   `json:"ebpf_available"`
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	if linuxsupervisor.IsChildMode(arguments) {
		if err := linuxsupervisor.RunChildHandshake(); err != nil {
			fmt.Fprintf(os.Stderr, "supervisor child failed: %v\n", err)
			return 126
		}
		return 0
	}
	flags := flag.NewFlagSet("phigon-linux-supervisor", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	cgroupRoot := flags.String("cgroup-root", "", "absolute delegated cgroup-v2 subtree")
	procRoot := flags.String("proc-root", "/proc", "procfs root for the supervised host")
	machineID := flags.String("machine-id", "", "paired Phigon machine ID")
	boundaryID := flags.String("boundary-id", "", "opaque execution boundary ID")
	handshakeTimeout := flags.Duration("handshake-timeout", 5*time.Second, "pre-exec verification timeout")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	commandArguments := flags.Args()
	if len(commandArguments) == 0 {
		fmt.Fprintln(os.Stderr, "an explicit command is required after the flags")
		return 2
	}
	helperPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve supervisor helper: %v\n", err)
		return 1
	}
	launcher, err := linuxsupervisor.NewLauncher(linuxsupervisor.Config{
		CgroupRoot:       *cgroupRoot,
		ProcRoot:         *procRoot,
		MachineID:        *machineID,
		HelperPath:       helperPath,
		HandshakeTimeout: *handshakeTimeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure Linux supervision: %v\n", err)
		return 1
	}
	boundary, err := launcher.CreateBoundary(*boundaryID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create execution boundary: %v\n", err)
		return 1
	}
	cleanup := func() {
		if cleanupErr := launcher.RemoveBoundary(boundary); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "remove empty execution boundary: %v\n", cleanupErr)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	launched, err := launcher.Launch(ctx, boundary, linuxsupervisor.LaunchSpec{
		Path:   commandArguments[0],
		Args:   commandArguments[1:],
		Env:    os.Environ(),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	if err != nil {
		cleanup()
		fmt.Fprintf(os.Stderr, "launch supervised command: %v\n", err)
		return 1
	}
	status := launchStatus{
		Managed:                        false,
		BoundaryMembershipVerified:     launched.BoundaryVerified,
		RequiresControlPlaneActivation: true,
		BoundaryID:                     boundary.ID,
		BoundaryIdentity:               boundary.NativeIdentity,
		ProcessKey:                     launched.Identity.StableKey,
		ProcessID:                      launched.Identity.PID,
		CoverageMode:                   launched.Coverage.ObservationMode,
		CoverageComplete:               launched.Coverage.Complete,
		EBPFAvailable:                  launched.Coverage.EBPFAvailable,
	}
	if err := json.NewEncoder(os.Stderr).Encode(status); err != nil {
		_ = launched.Command.Process.Kill()
		_ = launched.Command.Wait()
		cleanup()
		return 1
	}
	waitErr := launched.Command.Wait()
	cleanup()
	if waitErr == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		return exitError.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "supervised command failed: %v\n", waitErr)
	return 1
}
