//go:build !linux

package main

import "github.com/phigonai/observer/go/guardianos"

func runSandboxChild(_ []string) int                       { return fail(nil) }
func guardSandboxStdio(_ []guardianos.Profile, _ int) bool { return false }
