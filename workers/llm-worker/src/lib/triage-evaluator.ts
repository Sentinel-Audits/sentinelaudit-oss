import type { FindingTriageVerdict } from "./finding-triage";
import type { GoldSetFindingCase } from "./triage-goldset";

export interface GoldSetPrediction {
	id: string;
	verdict: FindingTriageVerdict;
	confidence?: number;
}

export interface TriageEvaluationRow {
	id: string;
	detector: string;
	tags: string[];
	expected: FindingTriageVerdict;
	actual: FindingTriageVerdict;
	score: number;
	passed: boolean;
}

export interface TriageEvaluationBucketSummary {
	total: number;
	passed: number;
	averageScore: number;
	verdictAccuracy: number;
}

export interface TriageEvaluationSummary {
	total: number;
	passed: number;
	averageScore: number;
	verdictAccuracy: number;
	confusion: Record<FindingTriageVerdict, Record<FindingTriageVerdict, number>>;
	byDetector: Record<string, TriageEvaluationBucketSummary>;
	byTag: Record<string, TriageEvaluationBucketSummary>;
	rows: TriageEvaluationRow[];
}

const verdictOrder: FindingTriageVerdict[] = [
	"untriaged",
	"likely_real",
	"needs_human_review",
	"likely_benign",
];

function buildEmptyConfusion() {
	const confusion = {} as Record<
		FindingTriageVerdict,
		Record<FindingTriageVerdict, number>
	>;
	for (const expected of verdictOrder) {
		confusion[expected] = {} as Record<FindingTriageVerdict, number>;
		for (const actual of verdictOrder) {
			confusion[expected][actual] = 0;
		}
	}
	return confusion;
}

function summarizeRows(rows: TriageEvaluationRow[]): TriageEvaluationBucketSummary {
	const total = rows.length;
	const passed = rows.filter((row) => row.passed).length;
	const exactMatches = rows.filter((row) => row.expected === row.actual).length;
	const totalScore = rows.reduce((sum, row) => sum + row.score, 0);

	return {
		total,
		passed,
		averageScore: total === 0 ? 0 : Number((totalScore / total).toFixed(3)),
		verdictAccuracy:
			total === 0 ? 0 : Number((exactMatches / total).toFixed(3)),
	};
}

export function scoreVerdictPair(
	expected: FindingTriageVerdict,
	actual: FindingTriageVerdict,
): number {
	if (expected === actual) return 1;

	const nearMisses = new Set([
		"likely_real|needs_human_review",
		"needs_human_review|likely_real",
		"needs_human_review|likely_benign",
		"likely_benign|needs_human_review",
	]);
	if (nearMisses.has(`${expected}|${actual}`)) {
		return 0.5;
	}

	return 0;
}

export function evaluateTriagePredictions(
	goldSet: GoldSetFindingCase[],
	predictions: GoldSetPrediction[],
): TriageEvaluationSummary {
	const predictionMap = new Map(predictions.map((prediction) => [prediction.id, prediction]));
	const confusion = buildEmptyConfusion();
	const rows: TriageEvaluationRow[] = [];
	const rowsByDetector = new Map<string, TriageEvaluationRow[]>();
	const rowsByTag = new Map<string, TriageEvaluationRow[]>();
	let exactMatches = 0;
	let totalScore = 0;

	for (const example of goldSet) {
		const actual =
			predictionMap.get(example.id)?.verdict || ("untriaged" as FindingTriageVerdict);
		const expected = example.expectedVerdict;
		const score = scoreVerdictPair(expected, actual);
		const passed = score >= 0.5;

		confusion[expected][actual] += 1;
		if (expected === actual) exactMatches += 1;
		totalScore += score;
		rows.push({
			id: example.id,
			detector: example.detector,
			tags: example.tags,
			expected,
			actual,
			score,
			passed,
		});

		const detectorRows = rowsByDetector.get(example.detector) || [];
		detectorRows.push(rows[rows.length - 1]);
		rowsByDetector.set(example.detector, detectorRows);

		for (const tag of example.tags) {
			const tagRows = rowsByTag.get(tag) || [];
			tagRows.push(rows[rows.length - 1]);
			rowsByTag.set(tag, tagRows);
		}
	}

	const total = goldSet.length;
	return {
		total,
		passed: rows.filter((row) => row.passed).length,
		averageScore: total === 0 ? 0 : Number((totalScore / total).toFixed(3)),
		verdictAccuracy: total === 0 ? 0 : Number((exactMatches / total).toFixed(3)),
		confusion,
		byDetector: Object.fromEntries(
			Array.from(rowsByDetector.entries()).map(([detector, detectorRows]) => [
				detector,
				summarizeRows(detectorRows),
			]),
		),
		byTag: Object.fromEntries(
			Array.from(rowsByTag.entries()).map(([tag, tagRows]) => [
				tag,
				summarizeRows(tagRows),
			]),
		),
		rows,
	};
}
