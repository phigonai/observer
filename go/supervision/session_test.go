package supervision

import (
	"testing"

	phigonv1 "github.com/phigonai/observer/go/gen/phigon/v1"
)

func TestManagedSessionRequiresOrderedStateTransitions(t *testing.T) {
	states := []phigonv1.SessionState{
		phigonv1.SessionState_SESSION_STATE_CREATING,
		phigonv1.SessionState_SESSION_STATE_BOUNDARY_READY,
		phigonv1.SessionState_SESSION_STATE_IDENTITY_READY,
		phigonv1.SessionState_SESSION_STATE_PROCESS_STARTING,
		phigonv1.SessionState_SESSION_STATE_ACTIVE,
		phigonv1.SessionState_SESSION_STATE_DRAINING,
		phigonv1.SessionState_SESSION_STATE_CLOSED,
	}
	activation := validActivation()
	for index := 0; index < len(states)-1; index++ {
		if err := ValidateTransition(states[index], states[index+1], &activation); err != nil {
			t.Fatalf("transition %s -> %s: %v", states[index], states[index+1], err)
		}
	}
	if err := ValidateTransition(
		phigonv1.SessionState_SESSION_STATE_CREATING,
		phigonv1.SessionState_SESSION_STATE_ACTIVE,
		&activation,
	); err == nil {
		t.Fatal("creating session skipped directly to active")
	}
}

func TestManagedSessionRejectsMismatchedOrUnconfirmedActivation(t *testing.T) {
	tests := map[string]func(*ActivationEvidence){
		"identity session":    func(value *ActivationEvidence) { value.IdentitySessionID = "other" },
		"identity boundary":   func(value *ActivationEvidence) { value.IdentityBoundaryID = "other" },
		"missing process key": func(value *ActivationEvidence) { value.RootProcessKey = "" },
		"process boundary":    func(value *ActivationEvidence) { value.ProcessBoundaryID = "other" },
		"sensor membership":   func(value *ActivationEvidence) { value.SensorMembershipValid = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			activation := validActivation()
			mutate(&activation)
			if err := ValidateTransition(
				phigonv1.SessionState_SESSION_STATE_PROCESS_STARTING,
				phigonv1.SessionState_SESSION_STATE_ACTIVE,
				&activation,
			); err == nil {
				t.Fatal("invalid managed activation was accepted")
			}
		})
	}
}

func validActivation() ActivationEvidence {
	return ActivationEvidence{
		AgentSessionID:        "session-a",
		ExecutionBoundaryID:   "boundary-a",
		IdentitySessionID:     "session-a",
		IdentityBoundaryID:    "boundary-a",
		RootProcessKey:        "machine:boot:pid:start:cgroup",
		ProcessBoundaryID:     "boundary-a",
		SensorMembershipValid: true,
	}
}
