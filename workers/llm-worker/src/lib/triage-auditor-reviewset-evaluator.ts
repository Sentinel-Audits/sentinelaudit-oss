import {
	applyDeterministicFindingTriages,
	getFindingBucket,
	getEffectiveInvariantKinds,
	type FindingWithTriage,
} from "./finding-triage";
import type { AuditorReviewCase } from "./triage-auditor-reviewset";

export interface AuditorReviewRow {
	id: string;
	shouldHeadline: boolean;
	actualHeadline: boolean;
	expectedBucket: AuditorReviewCase["expectedBucket"];
	actualBucket: AuditorReviewCase["expectedBucket"];
	expectedVerdict: AuditorReviewCase["expectedVerdict"];
	actualVerdict: AuditorReviewCase["expectedVerdict"] | "untriaged";
	expectedInvariantKinds: AuditorReviewCase["expectedInvariantKinds"];
	actualInvariantKinds: string[];
	headlineMatched: boolean;
	bucketMatched: boolean;
	verdictMatched: boolean;
	invariantMatched: boolean;
}

export interface AuditorReviewSummary {
	total: number;
	headlineAccuracy: number;
	bucketAccuracy: number;
	verdictAccuracy: number;
	invariantAccuracy: number;
	rows: AuditorReviewRow[];
}

export function evaluateAuditorReviewSet(
	reviewSet: AuditorReviewCase[],
): AuditorReviewSummary {
	const triaged = applyDeterministicFindingTriages(
		reviewSet.map((item) => item.finding) as FindingWithTriage[],
	);
	const triagedById = new Map(triaged.map((finding) => [finding.id, finding]));

	const rows: AuditorReviewRow[] = reviewSet.map((item) => {
		const finding = triagedById.get(item.id);
		const actualBucket = finding
			? getFindingBucket(finding)
			: ("research_note" as const);
		const actualVerdict = finding?.triage?.verdict || "untriaged";
		const actualHeadline = actualBucket === "report_finding";
		const expectedInvariantKinds = item.expectedInvariantKinds || [];
		const actualInvariantKinds = finding ? getEffectiveInvariantKinds(finding) : [];

		return {
			id: item.id,
			shouldHeadline: item.shouldHeadline,
			actualHeadline,
			expectedBucket: item.expectedBucket,
			actualBucket,
			expectedVerdict: item.expectedVerdict,
			actualVerdict,
			expectedInvariantKinds,
			actualInvariantKinds,
			headlineMatched: actualHeadline === item.shouldHeadline,
			bucketMatched: actualBucket === item.expectedBucket,
			verdictMatched: actualVerdict === item.expectedVerdict,
			invariantMatched: expectedInvariantKinds.every((kind) =>
				actualInvariantKinds.includes(kind),
			),
		};
	});

	const total = rows.length;
	const headlineMatched = rows.filter((row) => row.headlineMatched).length;
	const bucketMatched = rows.filter((row) => row.bucketMatched).length;
	const verdictMatched = rows.filter((row) => row.verdictMatched).length;
	const invariantMatched = rows.filter((row) => row.invariantMatched).length;

	return {
		total,
		headlineAccuracy:
			total === 0 ? 0 : Number((headlineMatched / total).toFixed(3)),
		bucketAccuracy:
			total === 0 ? 0 : Number((bucketMatched / total).toFixed(3)),
		verdictAccuracy:
			total === 0 ? 0 : Number((verdictMatched / total).toFixed(3)),
		invariantAccuracy:
			total === 0 ? 0 : Number((invariantMatched / total).toFixed(3)),
		rows,
	};
}
