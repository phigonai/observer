// guardian-runner owns the lifetime of one managed command and its contained
// descendants. Policy decisions remain in the hosted Guardian service.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/phigonai/observer/go/guardianos"
)

func main() { exitProcess(run()) }
func run() int {
	if len(os.Args) > 1 && os.Args[1] == "__relay" {
		return runOutputRelay()
	}
	// Discovery's Windows process listing: read-only, and no arguments.
	if len(os.Args) == 2 && os.Args[1] == "__processes" {
		return listProcesses(os.Stdout)
	}
	// Capture the actual observer before authorization or file IO can block.
	parentPID := os.Getppid()
	if len(os.Args) > 1 && os.Args[1] == "__sandbox" {
		return runSandboxChild(os.Args[2:])
	}
	digest := flag.String("sha256", "", "reviewed executable SHA-256")
	cwd := flag.String("cwd", "", "reviewed working directory")
	targetPID := flag.Int("kill-pid", 0, "exact administrator-authorized process")
	graceful := flag.Bool("graceful", false, "request a normal close without force")
	startedAt := flag.String("started-at", "", "expected process lifetime")
	cgroupRoot := flag.String("cgroup-root", "", "administrator-delegated Linux cgroup-v2 root")
	sandbox := flag.String("sandbox", "", "centrally assigned OS profiles")
	leaseConfig := flag.String("lease-config", "", "private one-use hosted lease bootstrap")
	tree := flag.Bool("tree", false, "include verified descendants and print a JSON report")
	ownChild := flag.Bool("own-child", false, "with --tree: force-stop a direct child of the caller instead of a lifetime given by --started-at")
	flag.Parse()
	if *targetPID != 0 && *tree {
		at, err := time.Parse(time.RFC3339Nano, *startedAt)
		report := treeReport{Outcome: "invalid"}
		switch {
		case *targetPID <= 4:
		case *targetPID == os.Getppid() || *targetPID == os.Getpid():
			report = treeReport{Outcome: "self_target"}
		case *ownChild && !*graceful:
			report = dispatchOwnChildTree(*targetPID, os.Getppid(), treeWait)
		case err == nil && !*ownChild:
			report = dispatchExactTree(*targetPID, at, *graceful, treeWait)
		}
		return writeTreeReport(os.Stdout, report)
	}
	if *targetPID != 0 {
		at, err := time.Parse(time.RFC3339Nano, *startedAt)
		if err != nil || *targetPID <= 4 || *targetPID == os.Getppid() || *targetPID == os.Getpid() {
			return fail(err)
		}
		if err := dispatchExactProcess(*targetPID, at, *graceful); err != nil {
			return fail(err)
		}
		return 0
	}
	args := flag.Args()
	if len(args) == 0 || !filepath.IsAbs(args[0]) || !filepath.IsAbs(*cwd) || len(*digest) != 64 {
		fmt.Fprintln(os.Stderr, "Phigon Guardian: invalid native execution manifest.")
		return 77
	}
	profiles, err := guardianos.Parse(*sandbox)
	if err != nil {
		return fail(err)
	}
	constraints, err := guardianos.ConstraintsFor(profiles)
	if err != nil {
		return fail(err)
	}
	if len(profiles) > 0 {
		if constraints.Platform != runtime.GOOS {
			return fail(fmt.Errorf("assigned sandbox is unsupported on this OS"))
		}
		if constraints.RequireCgroup && *cgroupRoot == "" {
			return fail(fmt.Errorf("company policy requires a delegated cgroup"))
		}
	}
	if constraints.Platform == "linux" && !guardSandboxStdio(profiles, parentPID) {
		return 77
	}
	lease, err := loadExecutionLease(*leaseConfig, args, *digest, *cwd, *cgroupRoot, *sandbox)
	if err != nil {
		return fail(err)
	}
	leaseContext, stopLease := context.WithCancel(context.Background())
	defer stopLease()
	if lease != nil {
		if err := lease.renew(leaseContext); err != nil {
			return fail(err)
		}
	}
	leaseLost := lease.watch(leaseContext, 10*time.Second)
	file, err := openExecutionFile(args[0])
	if err != nil {
		return fail(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	defer func() { _ = file.Close() }()
	if err != nil || hex.EncodeToString(hash.Sum(nil)) != *digest {
		fmt.Fprintln(os.Stderr, "Phigon Guardian: executable changed after authorization.")
		return 77
	}
	command := exec.Command(args[0], args[1:]...) // #nosec G204 -- Reviewed absolute manifest and executable digest verified above; native runner intentionally executes authorized commands without a shell.
	if constraints.Platform == "linux" {
		helper, err := os.Executable()
		if err != nil {
			return fail(err)
		}
		command = exec.Command(helper, append([]string{"__sandbox", *sandbox, *digest, *cwd, strconv.Itoa(parentPID)}, args...)...) // #nosec G204 -- Relaunch this trusted executable to apply the already validated sandbox manifest.
	}
	command.Dir = *cwd
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	cleanup, err := prepareContainment(command, *cgroupRoot, constraints)
	if err != nil {
		return fail(err)
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, terminationSignals()...)
	defer signal.Stop(signals)
	select {
	case <-leaseLost:
		cleanup()
		return fail(fmt.Errorf("native lease expired before launch"))
	case <-signals:
		cleanup()
		return fail(fmt.Errorf("native launch was cancelled"))
	default:
	}
	if !parentIsAlive(parentPID) {
		cleanup()
		return fail(fmt.Errorf("observer disconnected before launch"))
	}
	if err := command.Start(); err != nil {
		cleanup()
		return fail(err)
	}
	var runtimeExpired <-chan time.Time
	if constraints.Limits.MaxRuntimeSeconds > 0 {
		timer := time.NewTimer(time.Duration(constraints.Limits.MaxRuntimeSeconds) * time.Second)
		defer timer.Stop()
		runtimeExpired = timer.C
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	parentLost := make(chan struct{})
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ticker.C:
				if !parentIsAlive(parentPID) {
					close(parentLost)
					return
				}
			}
		}
	}()
	select {
	case err := <-exited:
		terminateContained(command, true)
		cleanup()
		if err == nil {
			return 0
		}
		if e, ok := err.(*exec.ExitError); ok {
			if e.ExitCode() < 0 {
				reportTermination("Phigon Guardian: managed process exited after an operating-system signal.")
				return 77
			}
			return e.ExitCode()
		}
		return 1
	case <-signals:
		terminateContained(command, true)
		waitForContainedExit(exited)
		cleanup()
		reportTermination("This agent and its managed children were stopped by Phigon Guardian.")
		return 77
	case <-parentLost:
		terminateContained(command, true)
		cleanup()
		reportTermination("Phigon Guardian stopped this agent because its supervisor disconnected.")
		return 77
	case <-leaseLost:
		terminateContained(command, true)
		waitForContainedExit(exited)
		cleanup()
		reportTermination("Phigon Guardian stopped this agent because its native execution lease was revoked or unavailable.")
		return 77
	case <-runtimeExpired:
		terminateContained(command, true)
		waitForContainedExit(exited)
		cleanup()
		reportTermination("Phigon Guardian stopped this agent because its company runtime limit was reached.")
		return 77
	}
}

// The observer may be stalled and the workload may have filled its stderr pipe.
// A user-facing notice must never hold the native supervisor (or its job) alive.
func reportTermination(message string) {
	finished := make(chan struct{})
	go func() {
		_, _ = fmt.Fprintln(os.Stderr, message)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(100 * time.Millisecond):
	}
}
func waitForContainedExit(exited <-chan error) {
	// Windows contains this supervisor in the same kill-on-close job. Return
	// immediately so process exit closes that job; waiting lets the workload run.
	if runtime.GOOS == "windows" {
		return
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
	}
}
func fail(err error) int {
	fmt.Fprintln(os.Stderr, "Phigon Guardian: native process containment could not be established; execution blocked.")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	return 77
}
