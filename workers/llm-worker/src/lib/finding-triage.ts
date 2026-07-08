import type { SemanticFacts } from "../types/vulnerability";
import {
	hasAccountingDimensionalContext,
	shouldRunDimensionalAnalysis,
} from "./dimensional-analysis";

export type FindingTriageVerdict =
	| "untriaged"
	| "likely_real"
	| "needs_human_review"
	| "likely_benign";

export type FindingState =
	| "raw_lead"
	| "manual_review_lead"
	| "triaged_likely_benign"
	| "triaged_needs_human_review"
	| "validated_candidate"
	| "confirmed_issue"
	| "rejected_noise";

export type FindingBucket =
	| "report_finding"
	| "needs_review"
	| "research_note";

export interface FindingTriageRecord {
	verdict: FindingTriageVerdict;
	confidence: number;
	rationale: string;
	invariantViolated: string;
	impactSummary: string;
	exploitPath: string[];
	blockers: string[];
	assumptions: string[];
	recommendedAction: string;
}

export interface FindingWithTriage {
	id: string;
	severity: string;
	analysisType?: string;
	findingState?: FindingState;
	reportBucket?: FindingBucket;
	originalId?: string;
	isExternal?: boolean;
	semanticFacts?: SemanticFacts;
	triage?: FindingTriageRecord;
}

export type InvariantKind =
	| "state_finalized_before_payout"
	| "upgrade_requires_explicit_authorization"
	| "share_asset_conversion_consistency"
	| "authenticated_input_required_for_privileged_action"
	| "decoded_indices_must_be_bounds_checked"
	| "message_provenance_must_be_verified_before_execution"
	| "mint_requires_authenticated_origin";

export function mapTriageVerdictToFindingState(
	verdict: FindingTriageVerdict,
	existingState: FindingState = "raw_lead",
): FindingState {
	if (verdict === "likely_real") {
		return "validated_candidate";
	}
	if (verdict === "needs_human_review") {
		return "triaged_needs_human_review";
	}
	if (verdict === "likely_benign") {
		return "triaged_likely_benign";
	}
	return existingState;
}

export function clampTriageConfidence(value: number): number {
	if (!Number.isFinite(value)) return 0;
	return Math.max(0, Math.min(100, Math.round(value)));
}

export function getFindingBucket(finding: FindingWithTriage): FindingBucket {
	if (finding.reportBucket) {
		return finding.reportBucket;
	}

	const state = String(finding.findingState || "raw_lead").toLowerCase();
	if (state === "confirmed_issue" || state === "validated_candidate") {
		return "report_finding";
	}
	if (state === "triaged_needs_human_review") {
		return "needs_review";
	}
	return "research_note";
}

function getDetectorId(finding: FindingWithTriage): string {
	return String(finding.originalId || "").toLowerCase().trim();
}

function hasTrustedBoundary(facts?: SemanticFacts): boolean {
	const boundary = facts?.trustBoundary || "unknown";
	return (
		boundary === "admin_only" ||
		boundary === "owner_only" ||
		boundary === "role_gated" ||
		boundary === "signature_authorized" ||
		boundary === "sender_restricted" ||
		boundary === "internal_only"
	);
}

function hasPublicReachability(facts?: SemanticFacts): boolean {
	return (
		facts?.visibility === "public" ||
		facts?.visibility === "external" ||
		facts?.trustBoundary === "public_or_unrestricted"
	);
}

function hasAttackerControlledSink(facts?: SemanticFacts): boolean {
	return Array.isArray(facts?.attackerControlledArgs) && facts.attackerControlledArgs.length > 0;
}

function getRecipientSource(
	facts?: SemanticFacts,
): NonNullable<SemanticFacts["provenanceSources"]>["recipientSource"] {
	return facts?.provenanceSources?.recipientSource || "unknown";
}

function getAmountSource(
	facts?: SemanticFacts,
): NonNullable<SemanticFacts["provenanceSources"]>["amountSource"] {
	return facts?.provenanceSources?.amountSource || "unknown";
}

function getTargetSource(
	facts?: SemanticFacts,
): NonNullable<SemanticFacts["provenanceSources"]>["targetSource"] {
	return facts?.provenanceSources?.targetSource || "unknown";
}

function hasStrongUserControlledProvenance(facts?: SemanticFacts): boolean {
	return (
		getRecipientSource(facts) === "user_arg" ||
		getAmountSource(facts) === "user_arg" ||
		getTargetSource(facts) === "user_arg"
	);
}

function hasBenignishProvenance(facts?: SemanticFacts): boolean {
	return (
		getRecipientSource(facts) === "msg_sender" ||
		getRecipientSource(facts) === "storage" ||
		getAmountSource(facts) === "balance_lookup" ||
		getAmountSource(facts) === "storage_lookup" ||
		getAmountSource(facts) === "signer_payload" ||
		getTargetSource(facts) === "storage" ||
		getTargetSource(facts) === "signer_payload"
	);
}

function hasTrustedSelfPayoutFlow(facts?: SemanticFacts): boolean {
	return (
		hasTrustedBoundary(facts) &&
		getRecipientSource(facts) === "msg_sender" &&
		getTargetSource(facts) !== "user_arg" &&
		!hasPostCallStateDependency(facts) &&
		!hasStateWritesAfterExternalCall(facts)
	);
}

function hasArithmeticControlledArgs(facts?: SemanticFacts): boolean {
	return (
		Array.isArray(facts?.arithmeticControlledArgs) &&
		facts.arithmeticControlledArgs.length > 0
	);
}

function getStoredInvariantKinds(facts?: SemanticFacts): InvariantKind[] {
	return (facts?.inferredInvariants || [])
		.map((invariant) => invariant.kind)
		.filter((kind): kind is InvariantKind =>
			kind === "state_finalized_before_payout" ||
			kind === "upgrade_requires_explicit_authorization" ||
			kind === "share_asset_conversion_consistency" ||
			kind === "authenticated_input_required_for_privileged_action" ||
			kind === "decoded_indices_must_be_bounds_checked" ||
			kind === "message_provenance_must_be_verified_before_execution" ||
			kind === "mint_requires_authenticated_origin",
		);
}

const PAYOUT_INVARIANT_DETECTORS = new Set([
	"arbitrary-send-eth",
	"arbitrary-send-erc20",
	"reentrancy",
	"reentrancy-eth",
	"reentrancy-benign",
]);

const UPGRADE_INVARIANT_DETECTORS = new Set(["unprotected-upgrade"]);

const ACCOUNTING_INVARIANT_DETECTORS = new Set([
	"divide-before-multiply",
	"incorrect-exp",
]);

const FIRST_PARTY_REVIEW_DETECTORS = new Set([
	"arbitrary-send-eth",
	"arbitrary-send-erc20",
	"reentrancy",
	"reentrancy-eth",
	"reentrancy-benign",
	"low-level-calls",
	"unchecked-lowlevel",
	"unchecked-transfer",
	"unused-return",
	"missing-zero-check",
	"uninitialized-local",
	"tx-origin",
	"divide-before-multiply",
	"incorrect-exp",
	"unprotected-upgrade",
]);

const ADVISORY_NOISE_DETECTORS = new Set([
	"assembly",
	"constable-states",
	"dead-code",
	"immutable-states",
	"naming-convention",
	"pragma",
	"solc-version",
	"too-many-digits",
	"unused-state",
	"unindexed-event-address",
	"unimplemented-functions",
	"shadowing-local",
	"reentrancy-events",
]);

function hasStateWritesAfterExternalCall(facts?: SemanticFacts): boolean {
	return Array.isArray(facts?.stateWritesAfterCalls) && facts.stateWritesAfterCalls.length > 0;
}

function hasExternalCall(facts?: SemanticFacts): boolean {
	return Array.isArray(facts?.externalCalls) && facts.externalCalls.length > 0;
}

function hasFinalizedStateBeforeExternalCall(facts?: SemanticFacts): boolean {
	return Boolean(facts?.stateFinalizedBeforeExternalCall);
}

function hasPostCallStateDependency(facts?: SemanticFacts): boolean {
	return Boolean(facts?.postCallStateDependsOnSuccess);
}

function hasEconomicallySensitiveState(facts?: SemanticFacts): boolean {
	const slots = Array.isArray(facts?.affectedStateSlots) ? facts.affectedStateSlots : [];
	return slots.some((slot) =>
		/\b(?:balance|balances|claim|claims|debt|debts|share|shares|supply|allowance|allowances|reserve|reserves|escrow|treasury)\b/i.test(
			slot,
		),
	);
}

function hasAccountingLinkedValueSource(facts?: SemanticFacts): boolean {
	const values = Array.isArray(facts?.valueSourceExpressions)
		? facts.valueSourceExpressions
		: [];
	return values.some((value) =>
		/(?:address\(this\)\.balance|balance|balances|claim|claims|debt|debts|share|shares|supply|reserve|reserves|escrow|treasury)/i.test(
			value,
		),
	);
}

function getInferredInvariants(facts?: SemanticFacts) {
	return Array.isArray(facts?.inferredInvariants) ? facts.inferredInvariants : [];
}

function hasInvariantKind(facts: SemanticFacts | undefined, kind: string): boolean {
	return getInferredInvariants(facts).some(
		(invariant) => String(invariant.kind || "") === kind,
	);
}

function hasSubsystem(
	facts: SemanticFacts | undefined,
	...kinds: Array<NonNullable<SemanticFacts["subsystems"]>[number]>
): boolean {
	const subsystems = Array.isArray(facts?.subsystems) ? facts.subsystems : [];
	return kinds.some((kind) => subsystems.includes(kind));
}

function hasAuthenticityBypassShape(facts?: SemanticFacts): boolean {
	return (
		hasSubsystem(facts, "verifier", "decoder", "message_handler") &&
		(hasInvariantKind(
			facts,
			"authenticated_input_required_for_privileged_action",
		) ||
			hasInvariantKind(
				facts,
				"message_provenance_must_be_verified_before_execution",
			) ||
			hasInvariantKind(facts, "decoded_indices_must_be_bounds_checked"))
	);
}

function hasPrivilegedConsequenceShape(facts?: SemanticFacts): boolean {
	return (
		hasSubsystem(facts, "admin_surface", "asset_manager", "executor") ||
		hasInvariantKind(facts, "mint_requires_authenticated_origin")
	);
}

function hasStructuredInputExploitability(facts?: SemanticFacts): boolean {
	return (
		hasPublicReachability(facts) &&
		hasAuthenticityBypassShape(facts) &&
		hasPrivilegedConsequenceShape(facts)
	);
}

function getPrimaryInvariantStatement(facts?: SemanticFacts): string | undefined {
	return getInferredInvariants(facts)[0]?.statement;
}

function hasAnyAuthConstraint(facts?: SemanticFacts): boolean {
	return (
		(Array.isArray(facts?.auth) && facts.auth.length > 0) ||
		(Array.isArray(facts?.modifiers) &&
			facts.modifiers.some((modifier) => /only|role|auth|sign/i.test(modifier)))
	);
}

function getPrimaryMismatchKind(facts?: SemanticFacts): string | undefined {
	return Array.isArray(facts?.dimensionalFacts?.mismatches) &&
		facts.dimensionalFacts.mismatches.length > 0
		? String(facts.dimensionalFacts.mismatches[0]?.kind || "") || undefined
		: undefined;
}

function formatDimensionalHypothesis(kind?: string): string | undefined {
	if (kind === "share_asset_confusion") {
		return "share and asset units can be mixed on the same accounting path";
	}
	if (kind === "price_amount_confusion") {
		return "price terms can be treated like token amounts in the same calculation";
	}
	if (kind === "scale_mismatch") {
		return "values may be combined across incompatible precision scales";
	}
	return undefined;
}

function getDimensionalMismatchKinds(facts?: SemanticFacts): string[] {
	return Array.isArray(facts?.dimensionalFacts?.mismatches)
		? facts.dimensionalFacts.mismatches.map((mismatch) => String(mismatch.kind || ""))
		: [];
}

function hasDimensionalMismatch(
	facts: SemanticFacts | undefined,
	...kinds: string[]
): boolean {
	const mismatchKinds = getDimensionalMismatchKinds(facts);
	return kinds.some((kind) => mismatchKinds.includes(kind));
}

function hasMeaningfulValueOrStateRisk(facts?: SemanticFacts): boolean {
	return (
		hasEconomicallySensitiveState(facts) ||
		hasAccountingLinkedValueSource(facts) ||
		hasPostCallStateDependency(facts) ||
		hasStateWritesAfterExternalCall(facts)
	);
}

function hasControlOrManipulationSignal(facts?: SemanticFacts): boolean {
	return (
		hasAttackerControlledSink(facts) ||
		hasStrongUserControlledProvenance(facts) ||
		hasArithmeticControlledArgs(facts)
	);
}

function isMediumOrHigherSeverity(finding: FindingWithTriage): boolean {
	const severity = String(finding?.severity || "").toLowerCase().trim();
	return (
		severity === "critical" ||
		severity === "high" ||
		severity === "medium"
	);
}

function shouldEscalateFirstPartyReview(
	finding: FindingWithTriage,
	triage?: FindingTriageRecord,
): boolean {
	if (finding?.isExternal === true) return false;

	const detectorId = getDetectorId(finding);
	const facts = finding.semanticFacts;
	const sensitiveDetector = FIRST_PARTY_REVIEW_DETECTORS.has(detectorId);
	const meaningfulSignals =
		hasPublicReachability(facts) ||
		hasMeaningfulValueOrStateRisk(facts) ||
		hasControlOrManipulationSignal(facts) ||
		hasExternalCall(facts);

	if (!sensitiveDetector && !isMediumOrHigherSeverity(finding)) {
		return false;
	}

	if (
		hasTrustedBoundary(facts) &&
		!hasPublicReachability(facts) &&
		!hasControlOrManipulationSignal(facts) &&
		!hasMeaningfulValueOrStateRisk(facts)
	) {
		return false;
	}

	if (
		triage &&
		triage.verdict === "likely_benign" &&
		!meaningfulSignals &&
		!isMediumOrHigherSeverity(finding)
	) {
		return false;
	}

	return meaningfulSignals || sensitiveDetector || isMediumOrHigherSeverity(finding);
}

function hasExploitabilityEvidence(
	detectorId: string,
	facts?: SemanticFacts,
): boolean {
	if (!facts) return false;

	if (
		detectorId === "silent-high-risk-review" &&
		hasStructuredInputExploitability(facts)
	) {
		return true;
	}

	const reachable = hasPublicReachability(facts);
	const control = hasControlOrManipulationSignal(facts);
	const statefulRisk = hasMeaningfulValueOrStateRisk(facts);
	const callRisk =
		hasExternalCall(facts) &&
		(hasStateWritesAfterExternalCall(facts) ||
			hasPostCallStateDependency(facts) ||
			!hasFinalizedStateBeforeExternalCall(facts));

	if (detectorId === "tx-origin") {
		return reachable;
	}

	if (detectorId === "unprotected-upgrade") {
		return (
			reachable &&
			(facts.attackerControlledArgs.includes("newImplementation") ||
				facts.attackerControlledArgs.includes("implementation"))
		);
	}

	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		return (
			reachable &&
			hasArithmeticControlledArgs(facts) &&
			(
				statefulRisk ||
				hasHighSignalDimensionalMismatch(facts) ||
				hasInvariantKind(facts, "share_asset_conversion_consistency")
			)
		);
	}

	if (
		detectorId === "reentrancy" ||
		detectorId === "reentrancy-eth" ||
		detectorId === "reentrancy-benign"
	) {
		return reachable && callRisk && statefulRisk;
	}

	if (
		detectorId === "arbitrary-send-eth" ||
		detectorId === "arbitrary-send-erc20" ||
		detectorId === "low-level-calls" ||
		detectorId === "unchecked-lowlevel" ||
		detectorId === "unchecked-transfer" ||
		detectorId === "unused-return"
	) {
		return (
			reachable &&
			hasExternalCall(facts) &&
			(
				control ||
				statefulRisk ||
				callRisk ||
				hasInvariantKind(facts, "state_finalized_before_payout")
			)
		);
	}

	if (detectorId === "missing-zero-check" || detectorId === "uninitialized-local") {
		return reachable && (control || statefulRisk);
	}

	return reachable && (control || statefulRisk || callRisk);
}

function hasHighSignalDimensionalMismatch(facts?: SemanticFacts): boolean {
	return hasDimensionalMismatch(
		facts,
		"share_asset_confusion",
		"price_amount_confusion",
		"scale_mismatch",
	);
}

export function getEffectiveInvariantKinds(
	finding: FindingWithTriage,
): InvariantKind[] {
	const detectorId = getDetectorId(finding);
	const facts = finding.semanticFacts;
	const inferred = new Set<InvariantKind>(getStoredInvariantKinds(facts));

	if (
		inferred.size === 0 &&
		PAYOUT_INVARIANT_DETECTORS.has(detectorId) &&
		hasPublicReachability(facts) &&
		hasExternalCall(facts) &&
		(hasStateWritesAfterExternalCall(facts) ||
			hasPostCallStateDependency(facts) ||
			hasEconomicallySensitiveState(facts) ||
			hasAccountingLinkedValueSource(facts))
	) {
		inferred.add("state_finalized_before_payout");
	}

	if (
		inferred.size === 0 &&
		UPGRADE_INVARIANT_DETECTORS.has(detectorId) &&
		(hasPublicReachability(facts) ||
			Array.isArray(facts?.attackerControlledArgs) &&
				(facts.attackerControlledArgs.includes("newImplementation") ||
					facts.attackerControlledArgs.includes("implementation")) ||
			Array.isArray(facts?.affectedStateSlots) &&
				facts.affectedStateSlots.some((slot) => /implementation/i.test(slot)))
	) {
		inferred.add("upgrade_requires_explicit_authorization");
	}

	if (
		inferred.size === 0 &&
		ACCOUNTING_INVARIANT_DETECTORS.has(detectorId) &&
		shouldRunDimensionalAnalysis(finding) &&
		hasArithmeticControlledArgs(facts) &&
		(hasAccountingDimensionalContext(facts) || hasHighSignalDimensionalMismatch(facts))
	) {
		inferred.add("share_asset_conversion_consistency");
	}

	return Array.from(inferred);
}

function buildDeterministicVerdict(
	finding: FindingWithTriage,
): FindingTriageVerdict {
	const detectorId = getDetectorId(finding);
	const facts = finding.semanticFacts;

	if (
		hasTrustedBoundary(facts) &&
		!hasPublicReachability(facts) &&
		detectorId !== "tx-origin"
	) {
		return "likely_benign";
	}

	if (detectorId === "arbitrary-send-eth" || detectorId === "arbitrary-send-erc20") {
		if (
			hasBridgeAdminFalsePositiveShape(facts) ||
			hasTrustedSelfPayoutFlow(facts) ||
			(hasTrustedBoundary(facts) && !hasAttackerControlledSink(facts)) ||
			(hasBenignishProvenance(facts) && !hasStrongUserControlledProvenance(facts))
		) {
			return "likely_benign";
		}
		if (
			hasPublicReachability(facts) &&
			hasExternalCall(facts) &&
			(hasAttackerControlledSink(facts) ||
				hasStrongUserControlledProvenance(facts) ||
				hasEconomicallySensitiveState(facts) ||
				hasAccountingLinkedValueSource(facts) ||
				hasPostCallStateDependency(facts))
		) {
			return "likely_real";
		}
		return "needs_human_review";
	}

	if (
		detectorId === "reentrancy" ||
		detectorId === "reentrancy-eth" ||
		detectorId === "reentrancy-benign"
	) {
		if (
			hasFinalizedStateBeforeExternalCall(facts) &&
			!hasPostCallStateDependency(facts)
		) {
			return "likely_benign";
		}
		if (
			hasPublicReachability(facts) &&
			hasExternalCall(facts) &&
			(hasStateWritesAfterExternalCall(facts) || hasPostCallStateDependency(facts))
		) {
			return detectorId === "reentrancy-benign"
				? "needs_human_review"
				: "likely_real";
		}
		return "needs_human_review";
	}

	if (detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") {
		if (hasBridgeAdminFalsePositiveShape(facts)) return "likely_benign";
		if (hasTrustedBoundary(facts) && !hasAttackerControlledSink(facts)) {
			return "likely_benign";
		}
		if (hasPublicReachability(facts) && hasAttackerControlledSink(facts)) {
			return hasEconomicallySensitiveState(facts) ||
				hasAccountingLinkedValueSource(facts) ||
				hasPostCallStateDependency(facts)
				? "likely_real"
				: "needs_human_review";
		}
		return "likely_benign";
	}

	if (detectorId === "unchecked-transfer") {
		if (hasTrustedBoundary(facts) && !hasPublicReachability(facts)) {
			return "likely_benign";
		}
		if (
			hasPublicReachability(facts) &&
			(hasAttackerControlledSink(facts) ||
				hasStateWritesAfterExternalCall(facts) ||
				hasPostCallStateDependency(facts))
		) {
			return hasEconomicallySensitiveState(facts) ||
				hasAccountingLinkedValueSource(facts)
				? "likely_real"
				: "needs_human_review";
		}
		return "likely_benign";
	}

	if (detectorId === "unused-return") {
		if (hasTrustedBoundary(facts) || !hasPublicReachability(facts)) {
			return "likely_benign";
		}
		return hasExternalCall(facts) &&
			(hasMeaningfulValueOrStateRisk(facts) || hasControlOrManipulationSignal(facts))
			? "needs_human_review"
			: "likely_benign";
	}

	if (detectorId === "missing-zero-check" || detectorId === "uninitialized-local") {
		return !hasPublicReachability(facts) || hasTrustedBoundary(facts)
			? "likely_benign"
			: "likely_real";
	}

	if (detectorId === "tx-origin") {
		return hasPublicReachability(facts) && hasExternalCall(facts)
			? "likely_real"
			: "needs_human_review";
	}

	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		if (
			!shouldRunDimensionalAnalysis(finding) ||
			hasTrustedBoundary(facts) ||
			!hasPublicReachability(facts)
		) {
			return "likely_benign";
		}
		return hasArithmeticControlledArgs(facts) ? "likely_real" : "needs_human_review";
	}

	if (detectorId === "unprotected-upgrade") {
		if (
			hasTrustedBoundary(facts) ||
			facts?.auth.includes("upgrade_authorized") ||
			facts?.modifiers.some((modifier) => /only(?:owner|role|proxy)/i.test(modifier))
		) {
			return "likely_benign";
		}
		if (
			hasPublicReachability(facts) &&
			(Array.isArray(facts?.attackerControlledArgs) &&
				(facts.attackerControlledArgs.includes("newImplementation") ||
					facts.attackerControlledArgs.includes("implementation")))
		) {
			return "likely_real";
		}
		return "needs_human_review";
	}

	if (detectorId === "dead-code" || detectorId === "naming-convention") {
		return "likely_benign";
	}

	return hasTrustedBoundary(facts) ? "likely_benign" : "needs_human_review";
}

function buildDeterministicConfidence(
	verdict: FindingTriageVerdict,
	finding: FindingWithTriage,
): number {
	const facts = finding.semanticFacts;
	if (verdict === "likely_real") {
		return hasPublicReachability(facts) &&
			(hasExternalCall(facts) || hasArithmeticControlledArgs(facts))
			? 88
			: 80;
	}
	if (verdict === "needs_human_review") return 72;
	if (verdict === "likely_benign") {
		return hasTrustedBoundary(facts) ? 84 : 68;
	}
	return 50;
}

export function buildDeterministicTriageRecord(
	finding: FindingWithTriage,
): FindingTriageRecord {
	const detectorId = getDetectorId(finding);
	const facts = finding.semanticFacts;
	const verdict = buildDeterministicVerdict(finding);
	const effectiveInvariantKinds = getEffectiveInvariantKinds(finding);
	const fallbackInvariant =
		effectiveInvariantKinds[0] === "state_finalized_before_payout"
			? "Funds movement and external payout paths should finalize accounting state before value leaves the contract."
			: effectiveInvariantKinds[0] === "upgrade_requires_explicit_authorization"
				? "Upgradeable entrypoints should require explicit authorization before implementation changes can occur."
				: effectiveInvariantKinds[0] === "share_asset_conversion_consistency"
					? "Share and asset conversion paths should preserve unit consistency across pricing and supply normalization."
					: "";

	return enrichTriageRecord(finding, {
		verdict,
		confidence: buildDeterministicConfidence(verdict, finding),
		rationale: buildDeterministicRationale(detectorId, facts),
		invariantViolated:
			buildInvariantViolated(detectorId, facts) || fallbackInvariant,
		impactSummary: buildImpactSummary(detectorId, facts),
		exploitPath: buildExploitPath(detectorId, facts),
		blockers: buildBlockers(detectorId, facts),
		assumptions: buildAssumptions(detectorId, facts),
		recommendedAction: buildRecommendedAction(detectorId, facts),
	});
}

export function applyDeterministicFindingTriages<T extends FindingWithTriage>(
	findings: T[],
): T[] {
	const triageMap = new Map(
		findings.map((finding) => [finding.id, buildDeterministicTriageRecord(finding)]),
	);
	return mergeFindingTriages(findings, triageMap);
}

function getDimensionalConfidenceBoost(
	detectorId: string,
	facts?: SemanticFacts,
): number {
	if (!facts) return 0;

	if (
		(detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") &&
		hasHighSignalDimensionalMismatch(facts)
	) {
		return 12;
	}

	if (
		(detectorId === "low-level-calls" ||
			detectorId === "unchecked-lowlevel" ||
			detectorId === "unchecked-transfer") &&
		hasHighSignalDimensionalMismatch(facts)
	) {
		return 6;
	}

	if (hasAccountingDimensionalContext(facts)) {
		return 4;
	}

	return 0;
}

function isBridgeOrMapperAdminFlow(facts?: SemanticFacts): boolean {
	const combined = [
		facts?.functionName,
		facts?.contractName,
		...(Array.isArray(facts?.modifiers) ? facts.modifiers : []),
	]
		.filter(Boolean)
		.join(" ")
		.toLowerCase();

	return (
		/\bbridge\b/.test(combined) ||
		/\bmapper\b/.test(combined) ||
		/\bwithdraw(?:coin|token)?liquidity\b/.test(combined) ||
		/\bsetdailylimit\b/.test(combined) ||
		/\bmultisig\b/.test(combined)
	);
}

function hasBridgeAdminFalsePositiveShape(facts?: SemanticFacts): boolean {
	return (
		Boolean(facts) &&
		isBridgeOrMapperAdminFlow(facts) &&
		hasTrustedBoundary(facts) &&
		!hasStrongUserControlledProvenance(facts) &&
		!hasEconomicallySensitiveState(facts) &&
		!hasAccountingLinkedValueSource(facts) &&
		!hasPostCallStateDependency(facts)
	);
}

function isStrongValidatedState(state: FindingState): boolean {
	return state === "confirmed_issue" || state === "validated_candidate";
}

function buildExploitPath(
	detectorId: string,
	facts?: SemanticFacts,
): string[] {
	if (ADVISORY_NOISE_DETECTORS.has(detectorId)) {
		return [];
	}

	const path: string[] = [];
	if (hasPublicReachability(facts)) {
		path.push("Reachable from a public or external entrypoint.");
	}
	if (hasAttackerControlledSink(facts)) {
		path.push(
			`Sensitive sink uses attacker-influenced inputs: ${facts?.attackerControlledArgs.join(", ")}.`,
		);
	}
	if (facts?.provenanceSources) {
		path.push(
			`Provenance: recipient=${getRecipientSource(facts)}, amount=${getAmountSource(facts)}, target=${getTargetSource(facts)}.`,
		);
	}
	if (hasArithmeticControlledArgs(facts)) {
		path.push(
			`Arithmetic uses user-influenced operands: ${facts?.arithmeticControlledArgs.join(", ")}.`,
		);
	}
	if (hasExternalCall(facts)) {
		path.push("Execution reaches an external interaction or value transfer.");
	}
	if (hasStateWritesAfterExternalCall(facts)) {
		path.push("State updates remain after the external interaction.");
	}
	if (hasFinalizedStateBeforeExternalCall(facts)) {
		path.push("State appears to be finalized before the external interaction.");
	}
	if (hasPostCallStateDependency(facts)) {
		path.push("Later state transitions still depend on the external call succeeding.");
	}
	if (Array.isArray(facts?.valueSourceExpressions) && facts.valueSourceExpressions.length > 0) {
		path.push(
			`Transferred value appears to derive from: ${facts.valueSourceExpressions.join(", ")}.`,
		);
	}
	if (hasEconomicallySensitiveState(facts)) {
		path.push(
			`State changes touch economically sensitive slots: ${facts?.affectedStateSlots.join(", ")}.`,
		);
	}
	const primaryInvariant = getPrimaryInvariantStatement(facts);
	if (primaryInvariant) {
		path.push(`Invariant under test: ${primaryInvariant}`);
	}
	if (hasAuthenticityBypassShape(facts)) {
		path.push(
			"Untrusted structured input reaches verification, decoding, or message-handling logic that appears security-critical.",
		);
	}
	if (hasInvariantKind(facts, "decoded_indices_must_be_bounds_checked")) {
		path.push(
			"Decoded index, count, or positional data may cross the verification path without strong bounds enforcement.",
		);
	}
	if (hasInvariantKind(facts, "message_provenance_must_be_verified_before_execution")) {
		path.push(
			"Message execution appears possible before provenance or inclusion authenticity is fully proven.",
		);
	}
	if (hasInvariantKind(facts, "authenticated_input_required_for_privileged_action")) {
		path.push(
			"Privileged behavior appears to depend on authenticated input, but the visible path may accept malformed or attacker-steered data first.",
		);
	}
	if (hasSubsystem(facts, "admin_surface")) {
		path.push(
			"Successful forgery or malformed input handling could reach an admin or governance-sensitive operation.",
		);
	}
	if (
		hasSubsystem(facts, "asset_manager") ||
		hasInvariantKind(facts, "mint_requires_authenticated_origin")
	) {
		path.push(
			"Successful authenticity bypass could unlock mint, burn, or asset-routing behavior with real balance consequences.",
		);
	}
	if (detectorId === "unchecked-transfer") {
		path.push("Token transfer success is not explicitly enforced before execution continues.");
	}
	if (detectorId === "tx-origin") {
		path.push("Authorization depends on tx.origin instead of msg.sender.");
	}
	if (detectorId === "unprotected-upgrade") {
		path.push("Implementation or upgrade control appears reachable from user-controlled input.");
	}
	if (detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") {
		path.push(
			getTargetSource(facts) === "user_arg"
				? "Attacker can steer execution into a user-chosen external target."
				: "External control flow leaves the protocol and may re-enter or fail in attacker-influenced ways.",
		);
	}
	if (detectorId === "unused-return") {
		path.push(
			"Execution may continue as though an external action succeeded even when the downstream call failed or returned an unsafe value.",
		);
	}
	if (detectorId === "missing-zero-check") {
		path.push(
			"Critical routing or configuration input can silently resolve to the zero address on a reachable path.",
		);
	}
	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		const mismatchHypothesis = formatDimensionalHypothesis(
			getPrimaryMismatchKind(facts),
		);
		path.push(
			mismatchHypothesis
				? `Accounting math suggests ${mismatchHypothesis}.`
				: "Reachable arithmetic can distort quotes, payout amounts, or share/accounting state before the protocol notices.",
		);
	}
	if (detectorId === "silent-high-risk-review" && hasStructuredInputExploitability(facts)) {
		path.push(
			"Combined path hypothesis: attacker-controlled structured input -> weak verification or decode boundary -> privileged message execution -> admin or asset-impacting action.",
		);
	}
	return path;
}

function buildBlockers(
	detectorId: string,
	facts?: SemanticFacts,
): string[] {
	const blockers: string[] = [];
	if (hasTrustedBoundary(facts)) {
		blockers.push(`Trusted boundary detected: ${facts?.trustBoundary}.`);
	}
	if (facts?.auth.includes("upgrade_authorized")) {
		blockers.push("Upgrade authorization hook is present.");
	}
	if (facts?.modifiers.some((modifier) => /only(?:owner|role|proxy)/i.test(modifier))) {
		blockers.push(`Privileged modifier detected: ${facts.modifiers.join(", ")}.`);
	}
	if (!hasPublicReachability(facts)) {
		blockers.push("No clearly public or external attack surface was extracted from the snippet.");
	}
	if (hasFinalizedStateBeforeExternalCall(facts)) {
		blockers.push("State appears finalized before the external interaction.");
	}
	if (hasBenignishProvenance(facts) && !hasStrongUserControlledProvenance(facts)) {
		blockers.push("The visible sink provenance looks more constrained than a raw user-controlled argument.");
	}
	if (!hasEconomicallySensitiveState(facts) && detectorId !== "tx-origin") {
		blockers.push("No clearly economically sensitive state slot was extracted around the call path.");
	}
	if (!hasAttackerControlledSink(facts) && detectorId !== "tx-origin") {
		blockers.push("No attacker-controlled sensitive argument was extracted.");
	}
	if (
		(detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") &&
		!hasArithmeticControlledArgs(facts)
	) {
		blockers.push("No user-influenced arithmetic operands were extracted from the snippet.");
	}
	if (!hasExploitabilityEvidence(detectorId, facts) && detectorId !== "tx-origin") {
		blockers.push(
			"Exploitability evidence is still incomplete for headline promotion: the current facts do not yet tie attacker reachability to meaningful value, state, or control-flow impact.",
		);
	}
	if (getInferredInvariants(facts).length === 0) {
		blockers.push(
			"No repo-local invariant was inferred for this path yet, so the finding still leans on detector semantics more than protocol-specific guarantees.",
		);
	}
	if (
		(detectorId === "low-level-calls" ||
			detectorId === "unchecked-lowlevel" ||
			detectorId === "unchecked-transfer") &&
		getTargetSource(facts) !== "user_arg" &&
		!hasPostCallStateDependency(facts)
	) {
		blockers.push(
			"The visible call path does not yet prove attacker-steerable target selection or a concrete post-call state failure.",
		);
	}
	if (
		(detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") &&
		!hasHighSignalDimensionalMismatch(facts)
	) {
		blockers.push(
			"No concrete scale or unit mismatch was extracted yet, so the math issue may still be precision noise rather than an exploitable accounting bug.",
		);
	}
	if (
		detectorId === "silent-high-risk-review" &&
		!hasStructuredInputExploitability(facts)
	) {
		blockers.push(
			"The current path hints at risky verification or message handling, but it does not yet tie malformed input acceptance to a concrete privileged consequence.",
		);
	}
	return blockers;
}

function buildAssumptions(
	detectorId: string,
	facts?: SemanticFacts,
): string[] {
	const assumptions: string[] = [];
	if (!facts?.functionName) {
		assumptions.push("Function-level extraction may be incomplete for this snippet.");
	}
	if (detectorId === "unprotected-upgrade") {
		assumptions.push("Inherited proxy wiring and storage layout are not fully visible in the snippet.");
	}
	if (
		detectorId === "reentrancy" ||
		detectorId === "reentrancy-eth" ||
		detectorId === "reentrancy-benign"
	) {
		assumptions.push("A meaningful callback path must be reachable for exploitation.");
	}
	if (
		detectorId === "tx-origin" ||
		detectorId === "low-level-calls" ||
		detectorId === "unchecked-lowlevel"
	) {
		assumptions.push(
			"Exploitability depends on an attacker being able to introduce an intermediary contract or malicious callee into the call chain.",
		);
	}
	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		assumptions.push(
			"Math impact depends on the protocol using this path in real pricing, payout, share, or collateral calculations.",
		);
	}
	if (detectorId === "silent-high-risk-review") {
		assumptions.push(
			"Exploitability depends on malformed or attacker-controlled structured input being able to cross the verification boundary on a live path.",
		);
	}
	if (hasAnyAuthConstraint(facts) && !hasTrustedBoundary(facts)) {
		assumptions.push(
			"The visible auth checks may be incomplete if the snippet relies on inherited modifiers or surrounding workflow validation.",
		);
	}
	if (!facts || facts.visibility === "unknown") {
		assumptions.push("Visibility/auth extraction relied on partial snippet context.");
	}
	return assumptions;
}

function buildRecommendedAction(
	detectorId: string,
	facts?: SemanticFacts,
): string {
	if (detectorId === "silent-high-risk-review") {
		return hasStructuredInputExploitability(facts)
			? "Prove malformed structured input cannot bypass authenticity checks before any admin, mint, execute, or message-handling side effect occurs."
			: "Inspect verification, decode, and message-execution ordering; promote only after tying malformed input acceptance to a privileged side effect.";
	}
	if (detectorId === "unprotected-upgrade") {
		return "Confirm upgrade authorization through _authorizeUpgrade, ownership, and proxy-only guards before promoting.";
	}
	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		return hasArithmeticControlledArgs(facts)
			? "Verify whether user-controlled math can distort accounting, pricing, or payout calculations in reachable flows."
			: "Confirm whether the math issue affects any user-reachable accounting path before promotion.";
	}
	if (detectorId === "unchecked-transfer") {
		return hasTrustedBoundary(facts)
			? "Verify privileged token transfer paths either use SafeERC20-style wrappers or explicitly check transfer success before assuming accounting completion."
			: "Confirm whether a user-reachable token transfer can fail silently while later logic assumes success.";
	}
	if (detectorId === "unused-return") {
		return hasExploitabilityEvidence(detectorId, facts)
			? "Confirm whether the ignored return value gates meaningful accounting, payout, or authorization state in a user-reachable flow."
			: "Do not promote this on the ignored return alone; first prove that execution continues into meaningful state or value movement after the unchecked call.";
	}
	if (detectorId === "tx-origin") {
		return "Replace tx.origin authorization with msg.sender or explicit signature validation.";
	}
	if (detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") {
		return getTargetSource(facts) === "user_arg"
			? "Constrain target selection, validate returndata, and prove the protocol remains safe if the callee is malicious or reentrant."
			: "Prove the external call target is trusted, returndata is checked, and downstream state does not assume success unsafely.";
	}
	if (detectorId === "arbitrary-send-eth" || detectorId === "arbitrary-send-erc20") {
		return hasTrustedBoundary(facts)
			? "Verify the privileged payout path is intended and cannot be abused through role or signer compromise."
			: "Confirm who controls recipient and amount, then verify accounting is finalized before funds move.";
	}
	if (
		detectorId === "reentrancy" ||
		detectorId === "reentrancy-eth" ||
		detectorId === "reentrancy-benign"
	) {
		return "Confirm state is finalized before the external interaction or add reentrancy protection.";
	}
	return "Review the extracted trust boundary, user-controlled inputs, and remaining blockers before promotion.";
}

function buildInvariantViolated(
	detectorId: string,
	facts?: SemanticFacts,
): string {
	if (detectorId === "silent-high-risk-review") {
		const invariant = getPrimaryInvariantStatement(facts);
		if (invariant) return invariant;
		return "Untrusted structured input should never cross verification or decode boundaries and trigger privileged message, admin, or asset-affecting behavior without authenticated provenance.";
	}
	if (detectorId === "arbitrary-send-eth" || detectorId === "arbitrary-send-erc20") {
		const invariant = getPrimaryInvariantStatement(facts);
		if (invariant) return invariant;
		return hasTrustedBoundary(facts)
			? "Contract value movement should remain constrained to intended privileged or signer-authorized payout flows."
			: "Contract value should not be redirectable through attacker-controlled recipients or amounts from a reachable public path.";
	}
	if (
		detectorId === "reentrancy" ||
		detectorId === "reentrancy-eth" ||
		detectorId === "reentrancy-benign"
	) {
		return "Protocol state should be finalized before external callbacks can observe or reenter sensitive logic.";
	}
	if (detectorId === "tx-origin") {
		return "Authentication should bind to the immediate caller or explicit authorization, not tx.origin.";
	}
	if (detectorId === "unprotected-upgrade") {
		const invariant = getPrimaryInvariantStatement(facts);
		if (invariant) return invariant;
		return "Only explicitly authorized governance should be able to change implementation or upgrade targets.";
	}
	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		const invariant = getPrimaryInvariantStatement(facts);
		if (invariant) return invariant;
		return "User-reachable arithmetic should preserve economic and accounting precision across pricing, payout, and share calculations.";
	}
	if (detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") {
		return "External call success and target behavior should be validated before the protocol assumes value transfer or control-flow success.";
	}
	if (detectorId === "unchecked-transfer") {
		return "Token accounting should not assume ERC20 transfers succeeded unless success is enforced or SafeERC20-style wrappers are used.";
	}
	if (detectorId === "unused-return") {
		return "Protocol logic should not ignore external-call success when later state, payouts, or control-flow decisions rely on that outcome.";
	}
	if (detectorId === "missing-zero-check") {
		return "Critical address inputs should not silently resolve to the zero address in reachable configuration or value-routing paths.";
	}
	if (detectorId === "uninitialized-local") {
		return "Reachable execution should not depend on unset local values for branching, accounting, or authorization decisions.";
	}
	return "Sensitive protocol behavior should preserve authorization, accounting, and control-flow invariants in reachable code paths.";
}

function buildImpactSummary(
	detectorId: string,
	facts?: SemanticFacts,
): string {
	if (detectorId === "silent-high-risk-review") {
		return hasPrivilegedConsequenceShape(facts)
			? "If malformed or forged structured input is accepted, the path could escalate privilege, mint assets, or execute attacker-chosen protocol actions."
			: "If authenticity checks are weaker than they look, structured input may still drive sensitive protocol control flow unexpectedly.";
	}
	if (detectorId === "arbitrary-send-eth" || detectorId === "arbitrary-send-erc20") {
		return hasTrustedBoundary(facts)
			? "If the trusted boundary is weaker than expected, privileged funds movement could be abused or misconfigured."
			: "An attacker may be able to redirect contract funds, drain balances, or route payouts away from intended recipients.";
	}
	if (
		detectorId === "reentrancy" ||
		detectorId === "reentrancy-eth" ||
		detectorId === "reentrancy-benign"
	) {
		return hasFinalizedStateBeforeExternalCall(facts)
			? "If other hidden callback paths exist, reentry could still matter, but the visible snippet suggests state is largely settled before the external call."
			: "Successful reentry can enable repeated withdrawals, stale-balance reuse, or broken accounting across sensitive flows.";
	}
	if (detectorId === "tx-origin") {
		return "Phishing-style intermediary contracts could trigger privileged actions on behalf of a victim EOA.";
	}
	if (detectorId === "unprotected-upgrade") {
		return "A compromised or publicly reachable upgrade path could replace protocol logic, seize funds, or brick the system.";
	}
	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		const mismatchHypothesis = formatDimensionalHypothesis(
			getPrimaryMismatchKind(facts),
		);
		return hasArithmeticControlledArgs(facts)
			? mismatchHypothesis
				? `User-controlled math may distort quotes, payouts, or share accounting because ${mismatchHypothesis}.`
				: "User-controlled math may distort quotes, payouts, fee calculations, or share/accounting results."
			: mismatchHypothesis
				? `Math imprecision may be exploitable because ${mismatchHypothesis}.`
				: "Math imprecision may produce incorrect accounting or pricing if it sits on a user-reachable path.";
	}
	if (detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") {
		return getTargetSource(facts) === "user_arg"
			? "An attacker may be able to route protocol execution into a malicious callee, fake success conditions, or exploit reentrant post-call state."
			: "The protocol may continue after failed calls or interact with an unexpected callee in a way that loses funds or leaves state inconsistent.";
	}
	if (detectorId === "unchecked-transfer") {
		return "Silent token transfer failure can leave balances, payouts, or debt/accounting state assuming funds moved when they did not.";
	}
	if (detectorId === "unused-return") {
		return hasExploitabilityEvidence(detectorId, facts)
			? "Ignoring a meaningful return value can let the protocol continue after failed execution, leaving sensitive state or payouts out of sync with reality."
			: "Ignoring a return value may be a code-quality issue, but the current facts do not yet show a concrete attacker-driven loss path.";
	}
	if (detectorId === "missing-zero-check") {
		return getRecipientSource(facts) === "user_arg" || getTargetSource(facts) === "user_arg"
			? "User-controlled address flow may burn funds or permanently redirect operations to the zero address."
			: "Zero-address misconfiguration can burn funds, disable routing, or permanently break privileged control paths.";
	}
	if (detectorId === "uninitialized-local") {
		return "Unexpected default values may steer execution into unintended branches or corrupt downstream accounting assumptions.";
	}
	return "If exploitable, this issue could violate protocol safety assumptions and produce user-visible loss or broken state.";
}

function buildDeterministicRationale(
	detectorId: string,
	facts?: SemanticFacts,
): string {
	const parts: string[] = [];
	if (hasTrustedBoundary(facts)) {
		parts.push(`The snippet is protected by a ${facts?.trustBoundary} boundary.`);
	} else if (hasPublicReachability(facts)) {
		parts.push("The snippet appears reachable from a public or external entrypoint.");
	}
	if (hasAttackerControlledSink(facts)) {
		parts.push(
			`Sensitive behavior depends on attacker-controlled inputs (${facts?.attackerControlledArgs.join(", ")}).`,
		);
	}
	if (hasArithmeticControlledArgs(facts)) {
		parts.push(
			`Arithmetic depends on user-influenced operands (${facts?.arithmeticControlledArgs.join(", ")}).`,
		);
	}
	if (hasStateWritesAfterExternalCall(facts)) {
		parts.push("State changes remain after the external call, which increases exploitability risk.");
	}
	if (hasFinalizedStateBeforeExternalCall(facts)) {
		parts.push("Visible state-reset patterns suggest the contract tries to finalize sensitive state before the external call.");
	}
	if (hasPostCallStateDependency(facts)) {
		parts.push("Later state transitions still depend on the post-call path succeeding.");
	}
	if (facts?.provenanceSources) {
		parts.push(
			`Extracted provenance points to recipient=${getRecipientSource(facts)}, amount=${getAmountSource(facts)}, target=${getTargetSource(facts)}.`,
		);
	}
	if (hasEconomicallySensitiveState(facts)) {
		parts.push(
			`The affected state appears economically meaningful (${facts?.affectedStateSlots.join(", ")}).`,
		);
	}
	if (hasAccountingLinkedValueSource(facts)) {
		parts.push("The moved value appears tied to balance or accounting-derived state.");
	}
	if (
		(detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") &&
		getTargetSource(facts) === "user_arg"
	) {
		parts.push(
			"The extracted provenance suggests the external target itself may be attacker-chosen, which is much closer to a real exploit setup than a generic low-level call warning.",
		);
	}
	if (hasAccountingDimensionalContext(facts)) {
		parts.push(
			"The extracted path shows accounting or unit-sensitive signals where dimensional mistakes could matter.",
		);
	}
	if (getInferredInvariants(facts).length > 0) {
		parts.push(
			`Inferred invariant coverage: ${getInferredInvariants(facts)
				.map((invariant) => invariant.kind)
				.join(", ")}.`,
		);
	}
	if (
		Array.isArray(facts?.dimensionalFacts?.mismatches) &&
		facts.dimensionalFacts.mismatches.length > 0
	) {
		parts.push(
			`Potential unit mismatch observed: ${facts.dimensionalFacts.mismatches
				.map((mismatch) => mismatch.kind)
				.join(", ")}.`,
		);
	}
	if (detectorId === "unprotected-upgrade" && facts?.auth.includes("upgrade_authorized")) {
		parts.push("Upgrade authorization is explicitly present in the extracted function context.");
	}
	if (detectorId === "tx-origin") {
		parts.push("Authorization uses tx.origin, which is vulnerable to phishing-mediated call chains.");
	}
	if (detectorId === "missing-zero-check") {
		parts.push(
			"A zero-address sink here would be irreversible, so exploitability depends on whether the bad address can be attacker-controlled or misconfigured on a live path.",
		);
	}
	if (detectorId === "unchecked-transfer") {
		parts.push("The snippet appears to rely on ERC20 transfer side effects without proving the transfer actually succeeded.");
	}
	if (detectorId === "unused-return") {
		parts.push("The snippet appears to ignore an external return value, so exploitability depends on whether later logic assumes success on a meaningful path.");
	}
	return parts.join(" ").trim();
}

function enrichTriageRecord(
	finding: FindingWithTriage,
	triage: FindingTriageRecord,
): FindingTriageRecord {
	const detectorId = getDetectorId(finding);
	const facts = finding.semanticFacts;
	const suppressExploitPathBackfill =
		ADVISORY_NOISE_DETECTORS.has(detectorId) &&
		triage.verdict === "likely_benign";
	const exploitPath =
		Array.isArray(triage.exploitPath) && triage.exploitPath.length > 0
			? triage.exploitPath
			: suppressExploitPathBackfill
				? []
			: buildExploitPath(detectorId, facts);
	const blockers =
		Array.isArray(triage.blockers) && triage.blockers.length > 0
			? triage.blockers
			: buildBlockers(detectorId, facts);
	const assumptions =
		Array.isArray(triage.assumptions) && triage.assumptions.length > 0
			? triage.assumptions
			: buildAssumptions(detectorId, facts);
	const confidenceBoost = getDimensionalConfidenceBoost(detectorId, facts);
	return {
		...triage,
		confidence: clampTriageConfidence(
			Number(triage.confidence || 0) + confidenceBoost,
		),
		rationale:
			String(triage.rationale || "").trim() ||
			buildDeterministicRationale(detectorId, facts),
		invariantViolated:
			String(triage.invariantViolated || "").trim() ||
			buildInvariantViolated(detectorId, facts),
		impactSummary:
			String(triage.impactSummary || "").trim() ||
			buildImpactSummary(detectorId, facts),
		exploitPath,
		blockers,
		assumptions,
		recommendedAction:
			String(triage.recommendedAction || "").trim() ||
			buildRecommendedAction(detectorId, facts),
	};
}

function applyDetectorFactPolicy(
	finding: FindingWithTriage,
	state: FindingState,
	triage: FindingTriageRecord,
): { state: FindingState; reportBucket: FindingBucket } | null {
	const detectorId = getDetectorId(finding);
	const facts = finding.semanticFacts;

	if (detectorId === "arbitrary-send-eth" || detectorId === "arbitrary-send-erc20") {
		if (hasBridgeAdminFalsePositiveShape(facts)) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}

		if (hasTrustedSelfPayoutFlow(facts)) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}

		if (
			(hasTrustedBoundary(facts) && !hasAttackerControlledSink(facts)) ||
			(hasBenignishProvenance(facts) && !hasStrongUserControlledProvenance(facts))
		) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}

		if (
			hasPublicReachability(facts) &&
			hasExternalCall(facts)
		) {
			if (
				isStrongValidatedState(state) &&
				!hasTrustedBoundary(facts) &&
				!hasBridgeAdminFalsePositiveShape(facts) &&
				!hasBenignishProvenance(facts) &&
				!hasAttackerControlledSink(facts)
			) {
				return { state, reportBucket: "report_finding" };
			}

			if (!hasAttackerControlledSink(facts)) {
				return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
			}

			if (!hasStrongUserControlledProvenance(facts) && hasBenignishProvenance(facts)) {
				return {
					state: "triaged_needs_human_review",
					reportBucket: "needs_review",
				};
			}
			if (
				hasEconomicallySensitiveState(facts) ||
				hasAccountingLinkedValueSource(facts) ||
				hasPostCallStateDependency(facts)
			) {
				if (isStrongValidatedState(state)) {
					return { state, reportBucket: "report_finding" };
				}
				return {
					state: "triaged_needs_human_review",
					reportBucket: "needs_review",
				};
			}
			if (isStrongValidatedState(state)) {
				return { state, reportBucket: "needs_review" };
			}
			return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
		}

		return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
	}

	if (
		detectorId === "reentrancy" ||
		detectorId === "reentrancy-eth" ||
		detectorId === "reentrancy-benign"
	) {
		if (
			hasFinalizedStateBeforeExternalCall(facts) &&
			!hasPostCallStateDependency(facts)
		) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}

		if (
			hasTrustedBoundary(facts) &&
			(hasFinalizedStateBeforeExternalCall(facts) ||
				!hasStateWritesAfterExternalCall(facts))
		) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}

		if (
			hasPublicReachability(facts) &&
			hasExternalCall(facts) &&
			(hasStateWritesAfterExternalCall(facts) || hasPostCallStateDependency(facts))
		) {
			const economicallySensitive =
				hasEconomicallySensitiveState(facts) || hasAccountingLinkedValueSource(facts);
			if (detectorId === "reentrancy-benign") {
				return {
					state: "triaged_needs_human_review",
					reportBucket: "needs_review",
				};
			}
			if (isStrongValidatedState(state) && economicallySensitive) {
				return { state, reportBucket: "report_finding" };
			}
			return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
		}

		return {
			state: triage.verdict === "likely_benign" ? "triaged_likely_benign" : state,
			reportBucket:
				triage.verdict === "likely_benign" ? "research_note" : "needs_review",
		};
	}

	if (detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") {
		if (hasBridgeAdminFalsePositiveShape(facts)) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}

		if (hasTrustedBoundary(facts) && !hasAttackerControlledSink(facts)) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}
		if (hasPublicReachability(facts) && hasAttackerControlledSink(facts)) {
			const economicallySensitive =
				hasEconomicallySensitiveState(facts) ||
				hasAccountingLinkedValueSource(facts) ||
				hasPostCallStateDependency(facts);
			if (isStrongValidatedState(state) && economicallySensitive) {
				return { state, reportBucket: "report_finding" };
			}
			return {
				state: isStrongValidatedState(state) ? state : "triaged_needs_human_review",
				reportBucket: "needs_review",
			};
		}
		return { state: "triaged_likely_benign", reportBucket: "research_note" };
	}

	if (detectorId === "unchecked-transfer") {
		if (hasTrustedBoundary(facts) && !hasPublicReachability(facts)) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}
		if (
			hasPublicReachability(facts) &&
			(hasAttackerControlledSink(facts) ||
				hasStateWritesAfterExternalCall(facts) ||
				hasPostCallStateDependency(facts))
		) {
			if (!hasStrongUserControlledProvenance(facts) && hasBenignishProvenance(facts)) {
				return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
			}
			if (
				!hasEconomicallySensitiveState(facts) &&
				!hasAccountingLinkedValueSource(facts)
			) {
				return { state: "triaged_likely_benign", reportBucket: "research_note" };
			}
			return {
				state: isStrongValidatedState(state) ? state : "triaged_needs_human_review",
				reportBucket: "needs_review",
			};
		}
		return { state: "triaged_likely_benign", reportBucket: "research_note" };
	}

	if (detectorId === "unused-return") {
		if (hasTrustedBoundary(facts) || !hasPublicReachability(facts)) {
			return { state: "triaged_likely_benign", reportBucket: "research_note" };
		}
		if (
			!hasExternalCall(facts) ||
			(!hasMeaningfulValueOrStateRisk(facts) && !hasControlOrManipulationSignal(facts))
		) {
			return { state: "triaged_likely_benign", reportBucket: "research_note" };
		}
		return {
			state: isStrongValidatedState(state) ? state : "triaged_needs_human_review",
			reportBucket: "needs_review",
		};
	}

	if (detectorId === "missing-zero-check" || detectorId === "uninitialized-local") {
		if (!hasPublicReachability(facts) || hasTrustedBoundary(facts)) {
			return { state: "triaged_likely_benign", reportBucket: "research_note" };
		}
		if (triage.verdict === "likely_real" || state === "triaged_needs_human_review") {
			return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
		}
		return { state: "triaged_likely_benign", reportBucket: "research_note" };
	}

	if (detectorId === "tx-origin") {
		if (hasPublicReachability(facts) && hasExternalCall(facts)) {
			if (isStrongValidatedState(state)) {
				return { state, reportBucket: "report_finding" };
			}
			return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
		}
		return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
	}

	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		if (!shouldRunDimensionalAnalysis(finding)) {
			return { state: "triaged_likely_benign", reportBucket: "research_note" };
		}
		if (hasTrustedBoundary(facts) || !hasPublicReachability(facts)) {
			return { state: "triaged_likely_benign", reportBucket: "research_note" };
		}
		const hasHighSignalMismatch = hasHighSignalDimensionalMismatch(facts);
		const economicallySensitive =
			hasEconomicallySensitiveState(facts) ||
			hasAccountingLinkedValueSource(facts) ||
			hasAccountingDimensionalContext(facts);
		if (
			hasArithmeticControlledArgs(facts) &&
			hasHighSignalMismatch &&
			economicallySensitive &&
			isStrongValidatedState(state)
		) {
			return { state, reportBucket: "report_finding" };
		}
		if (hasArithmeticControlledArgs(facts)) {
			return {
				state: isStrongValidatedState(state) ? state : "triaged_needs_human_review",
				reportBucket: "needs_review",
			};
		}
		return { state: "triaged_likely_benign", reportBucket: "research_note" };
	}

	if (detectorId === "unprotected-upgrade") {
		if (
			hasTrustedBoundary(facts) ||
			facts?.auth.includes("upgrade_authorized") ||
			facts?.modifiers.some((modifier) => /only(?:owner|role|proxy)/i.test(modifier))
		) {
			return {
				state: "triaged_likely_benign",
				reportBucket: "research_note",
			};
		}

		if (
			hasPublicReachability(facts) &&
			(facts?.attackerControlledArgs.includes("newImplementation") ||
				facts?.attackerControlledArgs.includes("implementation"))
		) {
			if (getTargetSource(facts) !== "user_arg") {
				return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
			}
			if (isStrongValidatedState(state)) {
				return { state, reportBucket: "needs_review" };
			}
			return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
		}

		return { state: "triaged_needs_human_review", reportBucket: "needs_review" };
	}

	if (detectorId === "silent-high-risk-review") {
		if (hasStructuredInputExploitability(facts)) {
			if (isStrongValidatedState(state)) {
				return { state, reportBucket: "report_finding" };
			}
			return {
				state: "triaged_needs_human_review",
				reportBucket: "needs_review",
			};
		}
		return {
			state: "triaged_needs_human_review",
			reportBucket: "needs_review",
		};
	}

	return null;
}

function applyPromotionPolicy(
	finding: FindingWithTriage,
	state: FindingState,
	triage: FindingTriageRecord,
): { state: FindingState; reportBucket: FindingBucket } {
	const detectorId = getDetectorId(finding);
	const isExternal = finding.isExternal === true;

	if (detectorId === "shadowing-local") {
		return {
			state: "triaged_likely_benign",
			reportBucket: "research_note",
		};
	}

	if (detectorId === "reentrancy-events") {
		return {
			state: "triaged_likely_benign",
			reportBucket: "research_note",
		};
	}

	if (
		isExternal &&
		(detectorId === "unused-return" || detectorId === "divide-before-multiply")
	) {
		return {
			state: "triaged_likely_benign",
			reportBucket: "research_note",
		};
	}

	if (isExternal) {
		if (state === "confirmed_issue") {
			return { state, reportBucket: "needs_review" };
		}

		return { state, reportBucket: "research_note" };
	}

	const factPolicy = applyDetectorFactPolicy(finding, state, triage);
	if (factPolicy) {
		return factPolicy;
	}

	if (state === "confirmed_issue" || state === "validated_candidate") {
		if (!hasExploitabilityEvidence(detectorId, finding.semanticFacts)) {
			return { state, reportBucket: "needs_review" };
		}
		return { state, reportBucket: "report_finding" };
	}

	if (state === "triaged_needs_human_review") {
		return { state, reportBucket: "needs_review" };
	}

	if (shouldEscalateFirstPartyReview(finding, triage)) {
		if (
			(state === "confirmed_issue" || state === "validated_candidate") &&
			hasExploitabilityEvidence(detectorId, finding.semanticFacts)
		) {
			return { state, reportBucket: "report_finding" };
		}
		return {
			state: "triaged_needs_human_review",
			reportBucket: "needs_review",
		};
	}

	if (
		triage.verdict === "likely_benign" ||
		state === "triaged_likely_benign" ||
		state === "rejected_noise"
	) {
		return { state: "triaged_likely_benign", reportBucket: "research_note" };
	}

	return { state, reportBucket: "research_note" };
}

export function isCountableFinding(finding: FindingWithTriage): boolean {
	const bucket = getFindingBucket(finding);
	return bucket === "report_finding" || bucket === "needs_review";
}

export function mergeFindingTriages<T extends FindingWithTriage>(
	findings: T[],
	triageMap: Map<string, Partial<FindingTriageRecord>>,
): T[] {
	return findings.map((finding) => {
		const triageUpdate = triageMap.get(finding.id);
		if (!triageUpdate) return finding;

		const nextTriage: FindingTriageRecord = {
			verdict:
				(triageUpdate.verdict as FindingTriageVerdict | undefined) || "untriaged",
			confidence: clampTriageConfidence(Number(triageUpdate.confidence || 0)),
			rationale: String(triageUpdate.rationale || ""),
			invariantViolated: String(triageUpdate.invariantViolated || ""),
			impactSummary: String(triageUpdate.impactSummary || ""),
			exploitPath: Array.isArray(triageUpdate.exploitPath)
				? triageUpdate.exploitPath.map(String)
				: [],
			blockers: Array.isArray(triageUpdate.blockers)
				? triageUpdate.blockers.map(String)
				: [],
			assumptions: Array.isArray(triageUpdate.assumptions)
				? triageUpdate.assumptions.map(String)
				: [],
			recommendedAction: String(triageUpdate.recommendedAction || ""),
		};
		const enrichedTriage = enrichTriageRecord(finding, nextTriage);

		const nextFindingState = mapTriageVerdictToFindingState(
			enrichedTriage.verdict,
			finding.findingState || "raw_lead",
		);
		const promoted = applyPromotionPolicy(
			finding,
			nextFindingState,
			enrichedTriage,
		);

		return {
			...finding,
			findingState: promoted.state,
			reportBucket: promoted.reportBucket,
			triage: enrichedTriage,
		};
	});
}
