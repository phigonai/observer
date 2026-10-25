//go:build !linux

package linuxsupervisor

import "context"

type Launcher struct{}

func NewLauncher(Config) (*Launcher, error) {
	return nil, ErrUnsupported
}

func (*Launcher) CreateBoundary(string) (*Boundary, error) {
	return nil, ErrUnsupported
}

func (*Launcher) Launch(context.Context, *Boundary, LaunchSpec) (*LaunchedProcess, error) {
	return nil, ErrUnsupported
}

func (*Launcher) RemoveBoundary(*Boundary) error {
	return ErrUnsupported
}

func RunChildHandshake() error {
	return ErrUnsupported
}

func IsChildMode([]string) bool {
	return false
}

func ExitCode(error) int {
	return 1
}
