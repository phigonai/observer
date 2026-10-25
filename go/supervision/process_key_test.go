package supervision

import "testing"

func TestStableProcessKeyDoesNotReusePIDIdentity(t *testing.T) {
	first := ProcessKeyMaterial{
		MachineID:     "machine-a",
		BootID:        "boot-a",
		ProcessID:     4242,
		StartIdentity: "100000",
	}
	firstKey, err := StableProcessKey(first)
	if err != nil {
		t.Fatal(err)
	}
	sameKey, err := StableProcessKey(first)
	if err != nil || sameKey != firstKey {
		t.Fatalf("stable key = %q, %v; want %q", sameKey, err, firstKey)
	}
	reusedPID := first
	reusedPID.StartIdentity = "200000"
	secondKey, err := StableProcessKey(reusedPID)
	if err != nil {
		t.Fatal(err)
	}
	if secondKey == firstKey {
		t.Fatal("reused PID received the previous process-lifetime key")
	}
	if len(firstKey) != 64 || len(secondKey) != 64 {
		t.Fatalf("process keys are not SHA-256 digests: %q / %q", firstKey, secondKey)
	}
}

func TestStableProcessKeyFailsClosedOnPartialIdentity(t *testing.T) {
	if _, err := StableProcessKey(ProcessKeyMaterial{
		MachineID: "machine-a",
		BootID:    "boot-a",
		ProcessID: 42,
	}); err == nil {
		t.Fatal("partial process identity was accepted")
	}
}

func TestStableProcessKeyIsIndependentOfBoundaryMembership(t *testing.T) {
	material := ProcessKeyMaterial{
		MachineID:     "machine-a",
		BootID:        "boot-a",
		ProcessID:     42,
		StartIdentity: "100000",
	}
	beforeMove, err := StableProcessKey(material)
	if err != nil {
		t.Fatal(err)
	}
	afterMove, err := StableProcessKey(material)
	if err != nil || afterMove != beforeMove {
		t.Fatalf("boundary-independent key = %q, %v; want %q", afterMove, err, beforeMove)
	}
}

func TestSessionAndBoundaryIDsAreIndependentAndUnique(t *testing.T) {
	seen := make(map[string]struct{}, 2000)
	for range 1000 {
		sessionID, boundaryID := NewSessionIDs()
		if sessionID == boundaryID {
			t.Fatal("session and boundary received the same identity")
		}
		for _, value := range []string{sessionID, boundaryID} {
			if _, exists := seen[value]; exists {
				t.Fatalf("duplicate generated identity %s", value)
			}
			seen[value] = struct{}{}
		}
	}
}
