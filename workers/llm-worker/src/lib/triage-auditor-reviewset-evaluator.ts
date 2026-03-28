import {
	getFindingBucket,
	mergeFindingTriages,
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
	headlineMatched: boolean;
	bucketMatched: boolean;
	verdictMatched: boolean;
}

export interface AuditorReviewSummary {
	total: number;
	headlineAccuracy: number;
	bucketAccuracy: number;
	verdictAccuracy: number;
	rows: AuditorReviewRow[];
}

export function evaluateAuditorReviewSet(
	reviewSet: AuditorReviewCase[],
): AuditorReviewSummary {
	const triageMap = new Map(
		reviewSet.map((item) => [
			item.id,
			{
				verdict: item.expectedVerdict,
				confidence: 90,
			},
		]),
	);

	const triaged = mergeFindingTriages(
		reviewSet.map((item) => item.finding) as FindingWithTriage[],
		triageMap,
	);
	const triagedById = new Map(triaged.map((finding) => [finding.id, finding]));

	const rows: AuditorReviewRow[] = reviewSet.map((item) => {
		const finding = triagedById.get(item.id);
		const actualBucket = finding
			? getFindingBucket(finding)
			: ("research_note" as const);
		const actualVerdict = finding?.triage?.verdict || "untriaged";
		const actualHeadline = actualBucket === "report_finding";

		return {
			id: item.id,
			shouldHeadline: item.shouldHeadline,
			actualHeadline,
			expectedBucket: item.expectedBucket,
			actualBucket,
			expectedVerdict: item.expectedVerdict,
			actualVerdict,
			headlineMatched: actualHeadline === item.shouldHeadline,
			bucketMatched: actualBucket === item.expectedBucket,
			verdictMatched: actualVerdict === item.expectedVerdict,
		};
	});

	const total = rows.length;
	const headlineMatched = rows.filter((row) => row.headlineMatched).length;
	const bucketMatched = rows.filter((row) => row.bucketMatched).length;
	const verdictMatched = rows.filter((row) => row.verdictMatched).length;

	return {
		total,
		headlineAccuracy:
			total === 0 ? 0 : Number((headlineMatched / total).toFixed(3)),
		bucketAccuracy:
			total === 0 ? 0 : Number((bucketMatched / total).toFixed(3)),
		verdictAccuracy:
			total === 0 ? 0 : Number((verdictMatched / total).toFixed(3)),
		rows,
	};
}
