import {
	getFindingBucket,
	mergeFindingTriages,
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
	bucketMatched: boolean;
	verdictMatched: boolean;
}

export interface RepoBenchmarkSummary {
	fixtureId: string;
	total: number;
	bucketAccuracy: number;
	verdictAccuracy: number;
	rows: RepoBenchmarkRow[];
}

export function evaluateRepoBenchmark(
	fixture: RepoBenchmarkFixture,
): RepoBenchmarkSummary {
	const triageMap = new Map(
		fixture.expectations.map((item) => [
			item.id,
			{
				verdict: item.expectedVerdict,
				confidence: 90,
			},
		]),
	);

	const triaged = mergeFindingTriages(
		fixture.findings as FindingWithTriage[],
		triageMap,
	);

	const triagedById = new Map(triaged.map((finding) => [finding.id, finding]));
	const rows: RepoBenchmarkRow[] = fixture.expectations.map((expectation) => {
		const finding = triagedById.get(expectation.id);
		const actualBucket = finding
			? getFindingBucket(finding)
			: ("research_note" as const);
		const actualVerdict = finding?.triage?.verdict || "untriaged";

		return {
			id: expectation.id,
			expectedBucket: expectation.expectedBucket,
			actualBucket,
			expectedVerdict: expectation.expectedVerdict,
			actualVerdict,
			bucketMatched: actualBucket === expectation.expectedBucket,
			verdictMatched: actualVerdict === expectation.expectedVerdict,
		};
	});

	const total = rows.length;
	const matchedBuckets = rows.filter((row) => row.bucketMatched).length;
	const matchedVerdicts = rows.filter((row) => row.verdictMatched).length;

	return {
		fixtureId: fixture.id,
		total,
		bucketAccuracy:
			total === 0 ? 0 : Number((matchedBuckets / total).toFixed(3)),
		verdictAccuracy:
			total === 0 ? 0 : Number((matchedVerdicts / total).toFixed(3)),
		rows,
	};
}
