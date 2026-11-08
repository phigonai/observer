//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStandardStreamSocketsCannotCarryHostServices(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if err := validateSandboxStream(pair[0], false, os.Getpid()); err != nil {
		t.Fatalf("an unnamed stream socketpair is a data channel and stays allowed: %v", err)
	}
	if err := validateSandboxStream(pair[0], true, os.Getpid()); err != nil {
		t.Fatalf("the observer's own socketpair stays allowed under network denial: %v", err)
	}
	if err := validateSandboxStream(pair[0], true, os.Getpid()+1); err == nil {
		t.Fatal("under network denial a socketpair to another process must be rejected")
	}
	datagram, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(datagram[0])
	defer unix.Close(datagram[1])
	if err := validateSandboxStream(datagram[0], false, os.Getpid()); err == nil {
		t.Fatal("a datagram socketpair can be re-addressed to a host socket and must be rejected")
	}

	for _, address := range []string{filepath.Join(t.TempDir(), "service.sock"), "@phigon-test-" + filepath.Base(t.TempDir())} {
		listener, err := net.Listen("unix", address)
		if err != nil {
			t.Fatal(err)
		}
		client, err := net.Dial("unix", address)
		if err != nil {
			t.Fatal(err)
		}
		file, err := client.(*net.UnixConn).File()
		if err != nil {
			t.Fatal(err)
		}
		err = validateSandboxStream(int(file.Fd()), false, os.Getpid())
		if err == nil || !strings.Contains(err.Error(), "local service sockets") {
			t.Fatalf("a connected service socket (%s) reached the workload under network inherit: %v", address, err)
		}
		_ = file.Close()
		_ = client.Close()
		_ = listener.Close()
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	file, err := client.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validateSandboxStream(int(file.Fd()), false, os.Getpid()); err != nil {
		t.Fatalf("network inherit keeps TCP standard streams: %v", err)
	}
	if err := validateSandboxStream(int(file.Fd()), true, os.Getpid()); err == nil {
		t.Fatal("network denial must reject a TCP standard stream")
	}
}
