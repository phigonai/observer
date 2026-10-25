// Package supervision correlates independent evidence without overwriting the
// original agent, operating-system, or gateway claims.
package supervision

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	phigonv1 "github.com/phigonai/observer/go/gen/phigon/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AttributionInput is all evidence known for one observed action. Callers must
// not combine unrelated actions merely because their timestamps are close.
type AttributionInput struct {
	Evidence         []*phigonv1.EvidenceReference
	CoverageComplete bool
	// ParentAndTimingMatch is a deliberately weak fallback. It is considered
	// only when no boundary or authenticated gateway evidence is available.
	ParentAndTimingMatch bool
	EvaluatedAt          time.Time
}

// EvaluateAttribution returns an honest result for one action. Any disagreement
// wins over a high-confidence label, and known collection gaps win over an
// otherwise verified correlation.
func EvaluateAttribution(input AttributionInput) *phigonv1.AttributionResult {
	evidence := cloneEvidence(input.Evidence)
	trustedSessions := sessions(evidence, true)
	allSessions := sessions(evidence, false)
	reportedSessions := sourceReportedSessions(evidence)
	recommended := recommendedSession(
		trustedSessions,
		allSessions,
		reportedSessions,
	)
	conflict := evidenceConflicts(evidence, trustedSessions, allSessions)

	confidence, reason := confidenceFor(
		evidence,
		recommended,
		input.ParentAndTimingMatch,
	)
	if conflict {
		confidence = phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_CONFLICTING
		reason = "independent evidence claims disagree; the original claims were retained"
	} else if !input.CoverageComplete {
		confidence = phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_INCOMPLETE
		reason = "known sensor or collection gaps prevent a complete attribution"
	}

	evaluatedAt := input.EvaluatedAt.UTC()
	if evaluatedAt.IsZero() {
		evaluatedAt = time.Now().UTC()
	}
	return &phigonv1.AttributionResult{
		AttributionId:             uuid.NewString(),
		RecommendedAgentSessionId: recommended,
		Confidence:                confidence,
		Conflict:                  conflict,
		CoverageComplete:          input.CoverageComplete,
		Reason:                    reason,
		Evidence:                  evidence,
		EvaluatedAt:               timestamppb.New(evaluatedAt),
	}
}

func confidenceFor(
	evidence []*phigonv1.EvidenceReference,
	recommended string,
	parentAndTimingMatch bool,
) (phigonv1.AttributionConfidence, string) {
	if recommended == "" {
		return phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_UNATTRIBUTED,
			"no safe agent-session association exists"
	}

	var boundaryAndProcess bool
	osProcessKeys := make(map[string]struct{})
	gatewayProcessKeys := make(map[string]struct{})
	gatewayInvocations := make(map[string]struct{})
	independentInvocations := make(map[string]struct{})
	authenticatedGateway := false
	sourceReported := false
	onlySourceReported := len(evidence) > 0

	for _, claim := range evidence {
		if claim.GetClaimedAgentSessionId() != recommended {
			continue
		}
		if claim.GetSource() == phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE {
			sourceReported = true
		} else {
			onlySourceReported = false
		}
		if isOSEvidence(claim.GetSource()) &&
			claim.GetExecutionBoundaryId() != "" &&
			claim.GetProcessKey() != "" {
			boundaryAndProcess = true
			osProcessKeys[claim.GetProcessKey()] = struct{}{}
		}
		if isAuthenticatedGateway(claim) {
			authenticatedGateway = true
			if invocation := strings.TrimSpace(claim.GetInvocationId()); invocation != "" {
				gatewayInvocations[invocation] = struct{}{}
			}
			if claim.GetProcessKey() != "" {
				gatewayProcessKeys[claim.GetProcessKey()] = struct{}{}
			}
		} else if invocation := strings.TrimSpace(claim.GetInvocationId()); invocation != "" {
			independentInvocations[invocation] = struct{}{}
		}
	}

	invocationMatched := intersects(
		gatewayInvocations,
		independentInvocations,
	)
	stableProcessMatched := intersects(osProcessKeys, gatewayProcessKeys)
	if boundaryAndProcess && authenticatedGateway && invocationMatched &&
		stableProcessMatched {
		return phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_VERIFIED,
			"boundary, stable process, authenticated gateway, and invocation evidence agree"
	}
	if boundaryAndProcess {
		return phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_STRONGLY_CORRELATED,
			"operating-system boundary and stable process evidence agree"
	}
	if sourceReported && onlySourceReported {
		return phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_SOURCE_REPORTED,
			"only the agent-native source record identifies the session"
	}
	if parentAndTimingMatch {
		return phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_PROBABLE,
			"parent-process and bounded timing evidence agree without boundary proof"
	}
	return phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_UNATTRIBUTED,
		"evidence does not meet a safe attribution threshold"
}

func evidenceConflicts(
	evidence []*phigonv1.EvidenceReference,
	trustedSessions []string,
	allSessions []string,
) bool {
	if len(trustedSessions) > 1 || len(allSessions) > 1 {
		return true
	}
	if len(trustedSessions) == 1 && len(allSessions) == 1 &&
		trustedSessions[0] != allSessions[0] {
		return true
	}

	// All claims passed to this function describe one action. When a source
	// supplies a boundary or stable process hint, disagreement with trusted OS
	// evidence is material and must be surfaced instead of ignored.
	for _, value := range []func(*phigonv1.EvidenceReference) string{
		func(claim *phigonv1.EvidenceReference) string {
			return claim.GetExecutionBoundaryId()
		},
		func(claim *phigonv1.EvidenceReference) string {
			return claim.GetProcessKey()
		},
		func(claim *phigonv1.EvidenceReference) string {
			return claim.GetInvocationId()
		},
	} {
		trustedValues := make(map[string]struct{})
		untrustedValues := make(map[string]struct{})
		for _, claim := range evidence {
			identity := strings.TrimSpace(value(claim))
			if identity == "" {
				continue
			}
			if isTrustedIdentityClaim(claim) {
				trustedValues[identity] = struct{}{}
			} else {
				untrustedValues[identity] = struct{}{}
			}
		}
		if len(trustedValues) > 1 ||
			(len(trustedValues) == 0 && len(untrustedValues) > 1) {
			return true
		}
		for identity := range untrustedValues {
			if len(trustedValues) > 0 {
				if _, matches := trustedValues[identity]; !matches {
					return true
				}
			}
		}
	}
	return false
}

func recommendedSession(trusted, all, sourceReported []string) string {
	if len(trusted) == 1 {
		return trusted[0]
	}
	if len(trusted) == 0 && len(all) == 1 && len(sourceReported) == 1 {
		return sourceReported[0]
	}
	return ""
}

func sessions(
	evidence []*phigonv1.EvidenceReference,
	trustedOnly bool,
) []string {
	unique := make(map[string]struct{})
	for _, claim := range evidence {
		if claim == nil ||
			(trustedOnly && !isTrustedIdentityClaim(claim)) {
			continue
		}
		sessionID := strings.TrimSpace(claim.GetClaimedAgentSessionId())
		if sessionID != "" {
			unique[sessionID] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for sessionID := range unique {
		result = append(result, sessionID)
	}
	sort.Strings(result)
	return result
}

func sourceReportedSessions(
	evidence []*phigonv1.EvidenceReference,
) []string {
	unique := make(map[string]struct{})
	for _, claim := range evidence {
		if claim == nil ||
			claim.GetSource() !=
				phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE ||
			claim.GetClaimType() !=
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED {
			continue
		}
		sessionID := strings.TrimSpace(claim.GetClaimedAgentSessionId())
		if sessionID != "" {
			unique[sessionID] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for sessionID := range unique {
		result = append(result, sessionID)
	}
	sort.Strings(result)
	return result
}

// isTrustedIdentityClaim deliberately considers both origin and claim type.
// A gateway record is not identity proof merely because it uses a gateway
// source enum; it must also carry an authenticated claim. This keeps the
// correlator safe even before outer contract validation runs.
func isTrustedIdentityClaim(claim *phigonv1.EvidenceReference) bool {
	if claim == nil {
		return false
	}
	switch {
	case isOSEvidence(claim.GetSource()):
		return claim.GetClaimType() == phigonv1.ClaimType_CLAIM_TYPE_OBSERVED
	case isGateway(claim.GetSource()):
		return claim.GetClaimType() == phigonv1.ClaimType_CLAIM_TYPE_AUTHENTICATED
	case claim.GetSource() ==
		phigonv1.EvidenceSource_EVIDENCE_SOURCE_PHIGON_SUPERVISOR:
		return claim.GetClaimType() == phigonv1.ClaimType_CLAIM_TYPE_OBSERVED ||
			claim.GetClaimType() == phigonv1.ClaimType_CLAIM_TYPE_AUTHENTICATED
	default:
		return false
	}
}

func isOSEvidence(source phigonv1.EvidenceSource) bool {
	switch source {
	case phigonv1.EvidenceSource_EVIDENCE_SOURCE_LINUX_EBPF,
		phigonv1.EvidenceSource_EVIDENCE_SOURCE_WINDOWS_ETW,
		phigonv1.EvidenceSource_EVIDENCE_SOURCE_MACOS_ENDPOINT_SECURITY:
		return true
	default:
		return false
	}
}

func isGateway(source phigonv1.EvidenceSource) bool {
	switch source {
	case phigonv1.EvidenceSource_EVIDENCE_SOURCE_COMMAND_GATEWAY,
		phigonv1.EvidenceSource_EVIDENCE_SOURCE_MCP_GATEWAY,
		phigonv1.EvidenceSource_EVIDENCE_SOURCE_BROWSER_GATEWAY,
		phigonv1.EvidenceSource_EVIDENCE_SOURCE_MODEL_GATEWAY:
		return true
	default:
		return false
	}
}

func isAuthenticatedGateway(claim *phigonv1.EvidenceReference) bool {
	return claim != nil && isGateway(claim.GetSource()) &&
		claim.GetClaimType() == phigonv1.ClaimType_CLAIM_TYPE_AUTHENTICATED
}

func intersects(left, right map[string]struct{}) bool {
	for value := range left {
		if _, ok := right[value]; ok {
			return true
		}
	}
	return false
}

func cloneEvidence(
	evidence []*phigonv1.EvidenceReference,
) []*phigonv1.EvidenceReference {
	cloned := make([]*phigonv1.EvidenceReference, 0, len(evidence))
	for _, claim := range evidence {
		if claim == nil {
			continue
		}
		copy, ok := proto.Clone(claim).(*phigonv1.EvidenceReference)
		if !ok {
			panic(fmt.Sprintf("unexpected evidence clone type %T", claim))
		}
		cloned = append(cloned, copy)
	}
	return cloned
}
