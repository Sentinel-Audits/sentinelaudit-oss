import type { SemanticFacts } from "../types/vulnerability";

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

function hasArithmeticControlledArgs(facts?: SemanticFacts): boolean {
	return (
		Array.isArray(facts?.arithmeticControlledArgs) &&
		facts.arithmeticControlledArgs.length > 0
	);
}

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
	if (detectorId === "unchecked-transfer") {
		path.push("Token transfer success is not explicitly enforced before execution continues.");
	}
	if (detectorId === "tx-origin") {
		path.push("Authorization depends on tx.origin instead of msg.sender.");
	}
	if (detectorId === "unprotected-upgrade") {
		path.push("Implementation or upgrade control appears reachable from user-controlled input.");
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
	if (!facts || facts.visibility === "unknown") {
		assumptions.push("Visibility/auth extraction relied on partial snippet context.");
	}
	return assumptions;
}

function buildRecommendedAction(
	detectorId: string,
	facts?: SemanticFacts,
): string {
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
	if (detectorId === "tx-origin") {
		return "Replace tx.origin authorization with msg.sender or explicit signature validation.";
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
	if (detectorId === "arbitrary-send-eth" || detectorId === "arbitrary-send-erc20") {
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
		return "Only explicitly authorized governance should be able to change implementation or upgrade targets.";
	}
	if (detectorId === "divide-before-multiply" || detectorId === "incorrect-exp") {
		return "User-reachable arithmetic should preserve economic and accounting precision across pricing, payout, and share calculations.";
	}
	if (detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") {
		return "External call success and target behavior should be validated before the protocol assumes value transfer or control-flow success.";
	}
	if (detectorId === "unchecked-transfer") {
		return "Token accounting should not assume ERC20 transfers succeeded unless success is enforced or SafeERC20-style wrappers are used.";
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
		return hasArithmeticControlledArgs(facts)
			? "User-controlled math may distort quotes, payouts, fee calculations, or share/accounting results."
			: "Math imprecision may produce incorrect accounting or pricing if it sits on a user-reachable path.";
	}
	if (detectorId === "low-level-calls" || detectorId === "unchecked-lowlevel") {
		return "The protocol may continue after failed calls or interact with attacker-chosen targets in a way that loses funds or leaves state inconsistent.";
	}
	if (detectorId === "unchecked-transfer") {
		return "Silent token transfer failure can leave balances, payouts, or debt/accounting state assuming funds moved when they did not.";
	}
	if (detectorId === "missing-zero-check") {
		return "Zero-address misconfiguration can burn funds, disable routing, or permanently break privileged control paths.";
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
	if (detectorId === "unprotected-upgrade" && facts?.auth.includes("upgrade_authorized")) {
		parts.push("Upgrade authorization is explicitly present in the extracted function context.");
	}
	if (detectorId === "tx-origin") {
		parts.push("Authorization uses tx.origin, which is vulnerable to phishing-mediated call chains.");
	}
	if (detectorId === "unchecked-transfer") {
		parts.push("The snippet appears to rely on ERC20 transfer side effects without proving the transfer actually succeeded.");
	}
	return parts.join(" ").trim();
}

function enrichTriageRecord(
	finding: FindingWithTriage,
	triage: FindingTriageRecord,
): FindingTriageRecord {
	const detectorId = getDetectorId(finding);
	const facts = finding.semanticFacts;
	const exploitPath =
		Array.isArray(triage.exploitPath) && triage.exploitPath.length > 0
			? triage.exploitPath
			: buildExploitPath(detectorId, facts);
	const blockers =
		Array.isArray(triage.blockers) && triage.blockers.length > 0
			? triage.blockers
			: buildBlockers(detectorId, facts);
	const assumptions =
		Array.isArray(triage.assumptions) && triage.assumptions.length > 0
			? triage.assumptions
			: buildAssumptions(detectorId, facts);
	return {
		...triage,
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
		if (hasTrustedBoundary(facts) || !hasPublicReachability(facts)) {
			return { state: "triaged_likely_benign", reportBucket: "research_note" };
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
		return { state, reportBucket: "report_finding" };
	}

	if (state === "triaged_needs_human_review") {
		return { state, reportBucket: "needs_review" };
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
