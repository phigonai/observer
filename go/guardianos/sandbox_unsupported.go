//go:build !linux

package guardianos

import "fmt"

func Apply(profiles []Profile) error {
	if len(profiles) > 0 {
		return fmt.Errorf("this operating system cannot enforce the assigned Linux sandbox")
	}
	return nil
}
