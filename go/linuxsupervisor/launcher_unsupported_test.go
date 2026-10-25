//go:build !linux

package linuxsupervisor

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedLauncherFailsClosed(t *testing.T) {
	t.Parallel()
	if _, err := NewLauncher(Config{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NewLauncher error = %v", err)
	}
	launcher := &Launcher{}
	if _, err := launcher.Launch(context.Background(), nil, LaunchSpec{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Launch error = %v", err)
	}
}
