package supervision

import (
	"strings"
	"testing"
	"time"

	phigonv1 "github.com/phigonai/observer/go/gen/phigon/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAttributionVerifiedOnlyWhenIndependentIdentityEvidenceAgrees(t *testing.T) {
	result := EvaluateAttribution(AttributionInput{
		CoverageComplete: true,
		EvaluatedAt:      time.Date(2026, 8, 1, 8, 0, 0, 0, time.UTC),
		Evidence: []*phigonv1.EvidenceReference{
			claim("agent", phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE,
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED, "session-a", "boundary-a", "process-a", "invocation-a"),
			claim("os", phigonv1.EvidenceSource_EVIDENCE_SOURCE_LINUX_EBPF,
				phigonv1.ClaimType_CLAIM_TYPE_OBSERVED, "session-a", "boundary-a", "process-a", "invocation-a"),
			claim("gateway", phigonv1.EvidenceSource_EVIDENCE_SOURCE_COMMAND_GATEWAY,
				phigonv1.ClaimType_CLAIM_TYPE_AUTHENTICATED, "session-a", "boundary-a", "process-a", "invocation-a"),
		},
	})

	if result.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_VERIFIED ||
		result.GetConflict() || result.GetRecommendedAgentSessionId() != "session-a" {
		t.Fatalf("EvaluateAttribution() = %#v", result)
	}
}

func TestAttributionNeverHidesSourceAndBoundaryConflict(t *testing.T) {
	result := EvaluateAttribution(AttributionInput{
		CoverageComplete: true,
		Evidence: []*phigonv1.EvidenceReference{
			claim("agent", phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE,
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED, "codex-a", "codex-boundary", "forged-process", "invocation-a"),
			claim("os", phigonv1.EvidenceSource_EVIDENCE_SOURCE_LINUX_EBPF,
				phigonv1.ClaimType_CLAIM_TYPE_OBSERVED, "opencode-b", "opencode-boundary", "process-b", "invocation-a"),
			claim("gateway", phigonv1.EvidenceSource_EVIDENCE_SOURCE_COMMAND_GATEWAY,
				phigonv1.ClaimType_CLAIM_TYPE_AUTHENTICATED, "opencode-b", "opencode-boundary", "process-b", "invocation-a"),
		},
	})

	if !result.GetConflict() ||
		result.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_CONFLICTING ||
		result.GetRecommendedAgentSessionId() != "opencode-b" ||
		len(result.GetEvidence()) != 3 {
		t.Fatalf("EvaluateAttribution(conflict) = %#v", result)
	}
}

func TestAttributionReportsIncompleteCoverageAndMissingIdentity(t *testing.T) {
	incomplete := EvaluateAttribution(AttributionInput{
		CoverageComplete: false,
		Evidence: []*phigonv1.EvidenceReference{
			claim("os", phigonv1.EvidenceSource_EVIDENCE_SOURCE_LINUX_EBPF,
				phigonv1.ClaimType_CLAIM_TYPE_OBSERVED, "session-a", "boundary-a", "process-a", ""),
		},
	})
	if incomplete.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_INCOMPLETE ||
		!strings.Contains(incomplete.GetReason(), "gaps") {
		t.Fatalf("EvaluateAttribution(incomplete) = %#v", incomplete)
	}

	unattributed := EvaluateAttribution(AttributionInput{
		CoverageComplete: true,
		Evidence: []*phigonv1.EvidenceReference{
			claim("os", phigonv1.EvidenceSource_EVIDENCE_SOURCE_LINUX_EBPF,
				phigonv1.ClaimType_CLAIM_TYPE_OBSERVED, "", "boundary-a", "process-a", ""),
		},
	})
	if unattributed.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_UNATTRIBUTED ||
		unattributed.GetRecommendedAgentSessionId() != "" {
		t.Fatalf("EvaluateAttribution(unattributed) = %#v", unattributed)
	}
}

func TestSourceOnlyAttributionRemainsSourceReported(t *testing.T) {
	result := EvaluateAttribution(AttributionInput{
		CoverageComplete: true,
		Evidence: []*phigonv1.EvidenceReference{
			claim("agent", phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE,
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED, "session-a", "", "", ""),
		},
	})
	if result.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_SOURCE_REPORTED {
		t.Fatalf("EvaluateAttribution(source) confidence = %s", result.GetConfidence())
	}
}

func TestGatewaySourceWithoutAuthenticatedClaimIsNotTrusted(t *testing.T) {
	result := EvaluateAttribution(AttributionInput{
		CoverageComplete: true,
		Evidence: []*phigonv1.EvidenceReference{
			claim("gateway", phigonv1.EvidenceSource_EVIDENCE_SOURCE_COMMAND_GATEWAY,
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED, "forged-session", "boundary-a", "process-a", "invocation-a"),
		},
	})

	if result.GetRecommendedAgentSessionId() != "" ||
		result.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_UNATTRIBUTED {
		t.Fatalf("EvaluateAttribution(unauthenticated gateway) = %#v", result)
	}
}

func TestVerifiedRequiresAuthenticatedGatewayInvocationMatch(t *testing.T) {
	result := EvaluateAttribution(AttributionInput{
		CoverageComplete: true,
		Evidence: []*phigonv1.EvidenceReference{
			claim("agent", phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE,
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED, "session-a", "boundary-a", "process-a", "invocation-a"),
			claim("os", phigonv1.EvidenceSource_EVIDENCE_SOURCE_LINUX_EBPF,
				phigonv1.ClaimType_CLAIM_TYPE_OBSERVED, "session-a", "boundary-a", "process-a", "invocation-a"),
			claim("gateway", phigonv1.EvidenceSource_EVIDENCE_SOURCE_COMMAND_GATEWAY,
				phigonv1.ClaimType_CLAIM_TYPE_AUTHENTICATED, "session-a", "boundary-a", "process-a", ""),
		},
	})

	if result.GetConflict() ||
		result.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_STRONGLY_CORRELATED {
		t.Fatalf("EvaluateAttribution(missing gateway invocation) = %#v", result)
	}
}

func TestDifferingTrustedInvocationIDsAreConflicting(t *testing.T) {
	result := EvaluateAttribution(AttributionInput{
		CoverageComplete: true,
		Evidence: []*phigonv1.EvidenceReference{
			claim("os", phigonv1.EvidenceSource_EVIDENCE_SOURCE_LINUX_EBPF,
				phigonv1.ClaimType_CLAIM_TYPE_OBSERVED, "session-a", "boundary-a", "process-a", "invocation-a"),
			claim("gateway", phigonv1.EvidenceSource_EVIDENCE_SOURCE_COMMAND_GATEWAY,
				phigonv1.ClaimType_CLAIM_TYPE_AUTHENTICATED, "session-a", "boundary-a", "process-a", "invocation-b"),
		},
	})

	if !result.GetConflict() ||
		result.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_CONFLICTING {
		t.Fatalf("EvaluateAttribution(invocation conflict) = %#v", result)
	}
}

func TestPartialSourceIdentityOverlapRemainsConflicting(t *testing.T) {
	result := EvaluateAttribution(AttributionInput{
		CoverageComplete: true,
		Evidence: []*phigonv1.EvidenceReference{
			claim("os", phigonv1.EvidenceSource_EVIDENCE_SOURCE_LINUX_EBPF,
				phigonv1.ClaimType_CLAIM_TYPE_OBSERVED, "session-a", "boundary-a", "process-a", "invocation-a"),
			claim("gateway", phigonv1.EvidenceSource_EVIDENCE_SOURCE_COMMAND_GATEWAY,
				phigonv1.ClaimType_CLAIM_TYPE_AUTHENTICATED, "session-a", "boundary-a", "process-a", "invocation-a"),
			claim("agent-matching", phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE,
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED, "session-a", "boundary-a", "process-a", "invocation-a"),
			claim("agent-conflicting", phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE,
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED, "session-a", "boundary-b", "process-b", "invocation-b"),
		},
	})

	if !result.GetConflict() ||
		result.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_CONFLICTING {
		t.Fatalf("EvaluateAttribution(partial overlap) = %#v", result)
	}
}

func TestParentAndTimingFallbackNeverExceedsProbable(t *testing.T) {
	result := EvaluateAttribution(AttributionInput{
		CoverageComplete:     true,
		ParentAndTimingMatch: true,
		Evidence: []*phigonv1.EvidenceReference{
			claim("agent", phigonv1.EvidenceSource_EVIDENCE_SOURCE_AGENT_NATIVE,
				phigonv1.ClaimType_CLAIM_TYPE_SOURCE_REPORTED, "session-a", "", "", ""),
			claim("supervisor", phigonv1.EvidenceSource_EVIDENCE_SOURCE_PHIGON_SUPERVISOR,
				phigonv1.ClaimType_CLAIM_TYPE_OBSERVED, "session-a", "", "", ""),
		},
	})

	if result.GetConfidence() != phigonv1.AttributionConfidence_ATTRIBUTION_CONFIDENCE_PROBABLE {
		t.Fatalf("EvaluateAttribution(parent/timing) = %#v", result)
	}
}

func claim(
	id string,
	source phigonv1.EvidenceSource,
	claimType phigonv1.ClaimType,
	sessionID string,
	boundaryID string,
	processKey string,
	invocationID string,
) *phigonv1.EvidenceReference {
	return &phigonv1.EvidenceReference{
		EvidenceId:            id,
		Source:                source,
		ClaimType:             claimType,
		ClaimedAgentSessionId: sessionID,
		ExecutionBoundaryId:   boundaryID,
		ProcessKey:            processKey,
		InvocationId:          invocationID,
		EventDigest:           strings.Repeat("d", 64),
		ObservedAt:            timestamppb.New(time.Date(2026, 8, 1, 7, 59, 0, 0, time.UTC)),
	}
}
