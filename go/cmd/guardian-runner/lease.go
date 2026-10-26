package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// A private, one-use bootstrap file keeps the machine credential out of argv
// and the workload environment. Deployment must protect its parent directory.
type executionLease struct {
	Origin         string          `json:"origin"`
	Credential     string          `json:"credential"`
	Request        json.RawMessage `json:"request"`
	policyDigest   string
	manifestDigest string
	client         *http.Client
}

func loadExecutionLease(path string, command []string, digest, cwd, cgroup, sandbox string) (*executionLease, error) {
	if path == "" {
		return nil, nil
	} // Direct helper/kernel tests have no hosted grant.
	if !filepath.IsAbs(path) {
		return nil, errors.New("invalid lease bootstrap path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid lease bootstrap file")
	}
	file, err := os.Open(path) // #nosec G304 -- Operator-specified absolute bootstrap file; regular-file and opened identity checks guard substitution.
	if err != nil {
		return nil, errors.New("lease bootstrap unavailable")
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("lease bootstrap changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	err = errors.Join(err, file.Close())
	// Remove before launching any workload, including on invalid configuration.
	if removeErr := os.Remove(path); removeErr != nil {
		return nil, errors.New("lease bootstrap could not be removed")
	}
	if err != nil || len(data) > 128<<10 {
		return nil, errors.New("lease bootstrap exceeds limits")
	}
	var lease executionLease
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&lease) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid lease bootstrap")
	}
	origin, err := url.Parse(lease.Origin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") ||
		(origin.Scheme != "https" && !(origin.Scheme == "http" && (origin.Hostname() == "127.0.0.1" || origin.Hostname() == "::1" || origin.Hostname() == "localhost"))) {
		return nil, errors.New("invalid hosted lease origin")
	}
	if len(lease.Credential) < 16 || len(lease.Credential) > 1024 || strings.ContainsAny(lease.Credential, "\r\n\x00") {
		return nil, errors.New("invalid lease credential")
	}
	var request struct {
		PolicyDigest string `json:"policy_digest"`
		Manifest     string `json:"manifest"`
		Token        string `json:"token"`
	}
	if json.Unmarshal(lease.Request, &request) != nil || !hexDigest(request.PolicyDigest) || !hexDigest(request.Token) {
		return nil, errors.New("invalid lease binding")
	}
	var manifest struct {
		Executable string   `json:"executable"`
		Arguments  []string `json:"arguments"`
		Digest     string   `json:"executable_digest"`
		Cwd        string   `json:"working_directory"`
		Cgroup     string   `json:"cgroup_root"`
		Sandbox    string   `json:"sandbox"`
	}
	if json.Unmarshal([]byte(request.Manifest), &manifest) != nil || len(command) == 0 || manifest.Executable != command[0] || !slices.Equal(manifest.Arguments, command[1:]) ||
		manifest.Digest != digest || manifest.Cwd != cwd || manifest.Cgroup != cgroup || manifest.Sandbox != sandbox {
		return nil, errors.New("lease does not describe this native invocation")
	}
	hash := sha256.Sum256([]byte(request.Manifest))
	lease.manifestDigest = hex.EncodeToString(hash[:])
	lease.policyDigest = request.PolicyDigest
	lease.Origin = strings.TrimSuffix(lease.Origin, "/")
	lease.client = &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &lease, nil
}

func hexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// errLeaseUnavailable means the control plane could not be reached. Unlike a
// rejected or mismatched lease, it says nothing about authorization, so the
// watchdog tolerates one missed renewal while the lease is still valid.
var errLeaseUnavailable = errors.New("native lease renewal unavailable")

func (lease *executionLease) renew(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, lease.Origin+"/v1/machine/guardian/executions/renew", bytes.NewReader(lease.Request))
	if err != nil {
		return errors.New("native lease request unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+lease.Credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := lease.client.Do(request)
	if err != nil {
		return errLeaseUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("native execution lease rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return errors.New("invalid native lease response")
	}
	var result struct {
		Authorized     bool   `json:"authorized"`
		ManifestDigest string `json:"manifest_digest"`
		PolicyDigest   string `json:"policy_digest"`
		Seconds        int    `json:"lease_seconds"`
	}
	if json.Unmarshal(data, &result) != nil || !result.Authorized || result.ManifestDigest != lease.manifestDigest || result.PolicyDigest != lease.policyDigest || result.Seconds != 30 {
		return errors.New("native execution lease binding changed")
	}
	return nil
}

func (lease *executionLease) watch(ctx context.Context, interval time.Duration) <-chan error {
	if lease == nil {
		return nil
	}
	failed := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// The lease lasts 30s and renews every 10s, so a renewal that fails to
		// reach the server leaves time for the next one. A second consecutive
		// miss (or any rejection) ends the workload.
		lastRenewed := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := lease.renew(ctx); err != nil {
					if errors.Is(err, errLeaseUnavailable) && ctx.Err() == nil && time.Since(lastRenewed) < 2*interval {
						continue
					}
					if ctx.Err() == nil {
						failed <- err
					}
					return
				}
				lastRenewed = time.Now()
			}
		}
	}()
	return failed
}
