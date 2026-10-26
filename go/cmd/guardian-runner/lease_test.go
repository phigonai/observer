package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testLeaseBootstrap(t *testing.T, origin string, change func(map[string]any)) (string, []string) {
	t.Helper()
	directory := t.TempDir()
	command := []string{filepath.Join(directory, "program"), "argument"}
	manifest, _ := json.Marshal(map[string]any{"executable": command[0], "arguments": command[1:], "executable_digest": strings.Repeat("a", 64), "working_directory": directory, "cgroup_root": "", "sandbox": ""})
	data := map[string]any{"origin": origin, "credential": strings.Repeat("secret", 8), "request": map[string]any{"policy_digest": strings.Repeat("b", 64), "token": strings.Repeat("c", 64), "manifest": string(manifest)}}
	if change != nil {
		change(data)
	}
	encoded, _ := json.Marshal(data)
	file := filepath.Join(directory, "bootstrap.json")
	if err := os.WriteFile(file, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return file, command
}

func TestNativeLeaseBootstrapIsBoundAndConsumed(t *testing.T) {
	file, command := testLeaseBootstrap(t, "https://control.example", nil)
	lease, err := loadExecutionLease(file, command, strings.Repeat("a", 64), filepath.Dir(file), "", "")
	if err != nil || lease == nil {
		t.Fatalf("lease=%v err=%v", lease != nil, err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("machine credential file remains available to workload")
	}
	for _, origin := range []string{"http://control.example", "https://user:password@control.example", "https://control.example?token=x", "https://control.example/arbitrary/path"} {
		file, command = testLeaseBootstrap(t, origin, nil)
		if _, err := loadExecutionLease(file, command, strings.Repeat("a", 64), filepath.Dir(file), "", ""); err == nil {
			t.Error("unsafe origin accepted")
		}
	}
	file, command = testLeaseBootstrap(t, "https://control.example", nil)
	command[1] = "changed-argument"
	if _, err := loadExecutionLease(file, command, strings.Repeat("a", 64), filepath.Dir(file), "", ""); err == nil {
		t.Fatal("a grant authorized changed native arguments")
	}
}

func TestNativeLeaseRejectsRevocationAndWrongBindings(t *testing.T) {
	for _, mode := range []string{"valid", "denied", "wrong_policy", "wrong_manifest", "wrong_duration", "redirect", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			var lease *executionLease
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/machine/guardian/executions/renew" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("secret", 8) {
					t.Error("native request lost route or credential binding")
				}
				if mode == "redirect" {
					http.Redirect(w, r, "/credential-trap", http.StatusTemporaryRedirect)
					return
				}
				if mode == "denied" {
					w.WriteHeader(409)
					return
				}
				if mode == "oversize" {
					_, _ = w.Write([]byte(strings.Repeat("x", (64<<10)+1)))
					return
				}
				result := map[string]any{"authorized": true, "policy_digest": lease.policyDigest, "manifest_digest": lease.manifestDigest, "lease_seconds": 30}
				if mode == "wrong_policy" {
					result["policy_digest"] = strings.Repeat("d", 64)
				}
				if mode == "wrong_manifest" {
					result["manifest_digest"] = strings.Repeat("d", 64)
				}
				if mode == "wrong_duration" {
					result["lease_seconds"] = 30000
				}
				_ = json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			file, command := testLeaseBootstrap(t, server.URL, nil)
			var err error
			lease, err = loadExecutionLease(file, command, strings.Repeat("a", 64), filepath.Dir(file), "", "")
			if err != nil {
				t.Fatal(err)
			}
			err = lease.renew(t.Context())
			if (err == nil) != (mode == "valid") {
				t.Fatalf("renewal mode=%s err=%v", mode, err)
			}
		})
	}
}

func TestNativeLeaseWatchRunsWithoutObserverCallbacks(t *testing.T) {
	var calls atomic.Int32
	var lease *executionLease
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			w.WriteHeader(409)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"authorized": true, "policy_digest": lease.policyDigest, "manifest_digest": lease.manifestDigest, "lease_seconds": 30})
	}))
	defer server.Close()
	file, command := testLeaseBootstrap(t, server.URL, nil)
	var err error
	lease, err = loadExecutionLease(file, command, strings.Repeat("a", 64), filepath.Dir(file), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	select {
	case err := <-lease.watch(ctx, time.Millisecond*10):
		if err == nil {
			t.Fatal("revocation not reported")
		}
	case <-time.After(time.Second * 2):
		t.Fatal("native watchdog did not notice revocation")
	}
}

// dropConnection closes the TCP connection without answering, as a network
// blip would.
func dropConnection(w http.ResponseWriter) {
	connection, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = connection.Close()
	}
}

func testRenewalServer(t *testing.T, lease **executionLease, answer func(call int32) bool) *httptest.Server {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !answer(calls.Add(1)) {
			dropConnection(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"authorized": true, "policy_digest": (*lease).policyDigest, "manifest_digest": (*lease).manifestDigest, "lease_seconds": 30})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestNativeLeaseToleratesOneMissedRenewal(t *testing.T) {
	var lease *executionLease
	// Call 1 is the initial renewal; call 2 is dropped; later calls succeed.
	server := testRenewalServer(t, &lease, func(call int32) bool { return call != 2 })
	file, command := testLeaseBootstrap(t, server.URL, nil)
	var err error
	lease, err = loadExecutionLease(file, command, strings.Repeat("a", 64), filepath.Dir(file), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	select {
	case err := <-lease.watch(ctx, 50*time.Millisecond):
		t.Fatalf("one dropped renewal ended the workload: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestNativeLeaseGivesUpWhenRenewalStaysUnavailable(t *testing.T) {
	var lease *executionLease
	server := testRenewalServer(t, &lease, func(call int32) bool { return call == 1 })
	file, command := testLeaseBootstrap(t, server.URL, nil)
	var err error
	lease, err = loadExecutionLease(file, command, strings.Repeat("a", 64), filepath.Dir(file), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	select {
	case err := <-lease.watch(ctx, 20*time.Millisecond):
		if err == nil {
			t.Fatal("a lasting outage was not reported")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the workload kept running with no renewal")
	}
}
