package supervision

import (
	"fmt"

	phigonv1 "github.com/phigonai/observer/go/gen/phigon/v1"
)

// ActivationEvidence contains the independent facts required before a managed
// session may be reported active.
type ActivationEvidence struct {
	AgentSessionID        string
	ExecutionBoundaryID   string
	IdentitySessionID     string
	IdentityBoundaryID    string
	RootProcessKey        string
	ProcessBoundaryID     string
	SensorMembershipValid bool
}

// ValidateTransition enforces the launcher lifecycle. In particular, a
// managed session cannot skip boundary and identity preparation.
func ValidateTransition(
	current phigonv1.SessionState,
	next phigonv1.SessionState,
	activation *ActivationEvidence,
) error {
	allowed := allowedTransitions[current]
	if _, ok := allowed[next]; !ok {
		return fmt.Errorf("invalid session transition %s -> %s", current, next)
	}
	if next == phigonv1.SessionState_SESSION_STATE_ACTIVE {
		if err := ValidateManagedActivation(activation); err != nil {
			return err
		}
	}
	return nil
}

// ValidateManagedActivation ensures boundary, workload identity, root process,
// and sensor membership all refer to exactly the same session.
func ValidateManagedActivation(evidence *ActivationEvidence) error {
	if evidence == nil {
		return fmt.Errorf("managed activation evidence is required")
	}
	if evidence.AgentSessionID == "" || evidence.ExecutionBoundaryID == "" {
		return fmt.Errorf("session and boundary identity are required")
	}
	if evidence.IdentitySessionID != evidence.AgentSessionID ||
		evidence.IdentityBoundaryID != evidence.ExecutionBoundaryID {
		return fmt.Errorf("workload identity does not match session boundary")
	}
	if evidence.RootProcessKey == "" {
		return fmt.Errorf("stable root process key is required")
	}
	if evidence.ProcessBoundaryID != evidence.ExecutionBoundaryID {
		return fmt.Errorf("root process is not inside the registered boundary")
	}
	if !evidence.SensorMembershipValid {
		return fmt.Errorf("sensor has not confirmed boundary membership")
	}
	return nil
}

var allowedTransitions = map[phigonv1.SessionState]map[phigonv1.SessionState]struct{}{
	phigonv1.SessionState_SESSION_STATE_CREATING: setOf(
		phigonv1.SessionState_SESSION_STATE_BOUNDARY_READY,
		phigonv1.SessionState_SESSION_STATE_BOUNDARY_FAILED,
	),
	phigonv1.SessionState_SESSION_STATE_BOUNDARY_READY: setOf(
		phigonv1.SessionState_SESSION_STATE_IDENTITY_READY,
		phigonv1.SessionState_SESSION_STATE_IDENTITY_FAILED,
	),
	phigonv1.SessionState_SESSION_STATE_IDENTITY_READY: setOf(
		phigonv1.SessionState_SESSION_STATE_PROCESS_STARTING,
		phigonv1.SessionState_SESSION_STATE_PROCESS_FAILED,
	),
	phigonv1.SessionState_SESSION_STATE_PROCESS_STARTING: setOf(
		phigonv1.SessionState_SESSION_STATE_ACTIVE,
		phigonv1.SessionState_SESSION_STATE_PROCESS_FAILED,
		phigonv1.SessionState_SESSION_STATE_SENSOR_UNAVAILABLE,
		phigonv1.SessionState_SESSION_STATE_INCOMPLETE,
	),
	phigonv1.SessionState_SESSION_STATE_ACTIVE: setOf(
		phigonv1.SessionState_SESSION_STATE_DRAINING,
		phigonv1.SessionState_SESSION_STATE_SENSOR_UNAVAILABLE,
		phigonv1.SessionState_SESSION_STATE_ESCAPED,
		phigonv1.SessionState_SESSION_STATE_ORPHANED,
		phigonv1.SessionState_SESSION_STATE_INCOMPLETE,
	),
	phigonv1.SessionState_SESSION_STATE_DRAINING: setOf(
		phigonv1.SessionState_SESSION_STATE_CLOSED,
		phigonv1.SessionState_SESSION_STATE_ORPHANED,
		phigonv1.SessionState_SESSION_STATE_INCOMPLETE,
	),
}

func setOf(states ...phigonv1.SessionState) map[phigonv1.SessionState]struct{} {
	result := make(map[phigonv1.SessionState]struct{}, len(states))
	for _, state := range states {
		result[state] = struct{}{}
	}
	return result
}
