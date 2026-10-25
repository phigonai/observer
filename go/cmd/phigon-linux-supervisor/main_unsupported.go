//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "phigon-linux-supervisor requires Linux cgroup v2")
	os.Exit(2)
}
