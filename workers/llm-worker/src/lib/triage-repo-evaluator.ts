import {
	applyDeterministicFindingTriages,
	getFindingBucket,
	getEffectiveInvariantKinds,
	type FindingTriageVerdict,
	type FindingWithTriage,
} from "./finding-triage";
import type {
	RepoBenchmarkFixture,
	RepoBenchmarkExpectation,
} from "./triage-repo-benchmarks";

export interface RepoBenchmarkRow {
	id: string;
	expectedBucket: RepoBenchmarkExpectation["expectedBucket"];
	actualBucket: RepoBenchmarkExpectation["expectedBucket"];
	expectedVerdict: FindingTriageVerdict;
	actualVerdict: FindingTriageVerdict;
	expectedInvariantKinds: RepoBenchmarkExpectation["expectedInvariantKinds"];
	actualInvariantKinds: string[];
	bucketMatched: boolean;
	verdictMatched: boolean;
	invariantMatched: boolean;
}

export interface RepoBenchmarkSummary {
	fixtureId: string;
	total: number;
	bucketAccuracy: number;
	verdictAccuracy: number;
	invariantAccuracy: number;
	rows: RepoBenchmarkRow[];
}

export function evaluateRepoBenchmark(
	fixture: RepoBenchmarkFixture,
): RepoBenchmarkSummary {
	const triaged = applyDeterministicFindingTriages(
		fixture.findings as FindingWithTriage[],
	);

	const triagedById = new Map(triaged.map((finding) => [finding.id, finding]));
	const rows: RepoBenchmarkRow[] = fixture.expectations.map((expectation) => {
		const finding = triagedById.get(expectation.id);
		const actualBucket = finding
			? getFindingBucket(finding)
			: ("research_note" as const);
		const actualVerdict = finding?.triage?.verdict || "untriaged";
		const expectedInvariantKinds = expectation.expectedInvariantKinds || [];
		const actualInvariantKinds = finding
			? getEffectiveInvariantKinds(finding)
			: [];

		return {
			id: expectation.id,
			expectedBucket: expectation.expectedBucket,
			actualBucket,
			expectedVerdict: expectation.expectedVerdict,
			actualVerdict,
			expectedInvariantKinds,
			actualInvariantKinds,
			bucketMatched: actualBucket === expectation.expectedBucket,
			verdictMatched: actualVerdict === expectation.expectedVerdict,
			invariantMatched: expectedInvariantKinds.every((kind) =>
				actualInvariantKinds.includes(kind),
			),
		};
	});

	const total = rows.length;
	const matchedBuckets = rows.filter((row) => row.bucketMatched).length;
	const matchedVerdicts = rows.filter((row) => row.verdictMatched).length;
	const matchedInvariants = rows.filter((row) => row.invariantMatched).length;

	return {
		fixtureId: fixture.id,
		total,
		bucketAccuracy:
			total === 0 ? 0 : Number((matchedBuckets / total).toFixed(3)),
		verdictAccuracy:
			total === 0 ? 0 : Number((matchedVerdicts / total).toFixed(3)),
		invariantAccuracy:
			total === 0 ? 0 : Number((matchedInvariants / total).toFixed(3)),
		rows,
	};
}
