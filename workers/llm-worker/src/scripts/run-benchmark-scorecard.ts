import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { TRIAGE_REPO_BENCHMARKS } from "../lib/triage-repo-benchmarks";
import { evaluateRepoBenchmark } from "../lib/triage-repo-evaluator";
import { TRIAGE_SOURCE_BENCHMARKS } from "../lib/triage-source-benchmarks";
import { evaluateSourceBenchmark } from "../lib/triage-source-evaluator";
import { TRIAGE_SLITHER_BENCHMARKS } from "../lib/triage-slither-benchmarks";
import { evaluateSlitherBenchmark } from "../lib/triage-slither-evaluator";
import { TRIAGE_AUDITOR_REVIEWSET } from "../lib/triage-auditor-reviewset";
import { evaluateAuditorReviewSet } from "../lib/triage-auditor-reviewset-evaluator";

type AuditArtifact = {
	jobId?: string;
	projectId?: string;
	projectTitle?: string | null;
	improvementSignals?: Array<{ key: string }>;
	structuredSummary?: {
		totalFindings?: number;
		bucketCounts?: Record<string, number>;
		severityCounts?: Record<string, number>;
		factCoverage?: Record<string, number>;
	};
	sampleFindings?: Array<{
		dimensionalMismatchKinds?: string[];
		invariantKinds?: string[];
	}>;
	sampleFindingsByBucket?: Record<
		string,
		Array<{ dimensionalMismatchKinds?: string[]; invariantKinds?: string[] }>
	>;
};

type BenchmarkScorecard = {
	generatedAt: string;
	slitherBenchmarks: {
		fixtures: number;
		cases: number;
		transformAccuracy: number;
		bucketAccuracy: number;
		verdictAccuracy: number;
		invariantAccuracy: number;
		fixtureBreakdown: Array<{
			id: string;
			name: string;
			description: string;
			cases: number;
			transformAccuracy: number;
			bucketAccuracy: number;
			verdictAccuracy: number;
			invariantAccuracy: number;
		}>;
	};
	repoBenchmarks: {
		fixtures: number;
		cases: number;
		bucketAccuracy: number;
		verdictAccuracy: number;
		invariantAccuracy: number;
		fixtureBreakdown: Array<{
			id: string;
			name: string;
			description: string;
			cases: number;
			bucketAccuracy: number;
			verdictAccuracy: number;
			invariantAccuracy: number;
		}>;
	};
	sourceBenchmarks: {
		fixtures: number;
		cases: number;
		bucketAccuracy: number;
		verdictAccuracy: number;
		invariantAccuracy: number;
		fixtureBreakdown: Array<{
			id: string;
			name: string;
			description: string;
			cases: number;
			bucketAccuracy: number;
			verdictAccuracy: number;
			invariantAccuracy: number;
		}>;
	};
	auditorReviewSet: {
		cases: number;
		headlineAccuracy: number;
		bucketAccuracy: number;
		verdictAccuracy: number;
		invariantAccuracy: number;
		focusAreas: Array<{ tag: string; count: number }>;
		caseHighlights: Array<{
			id: string;
			title: string;
			detector: string;
			expectedBucket: string;
			shouldHeadline: boolean;
		}>;
	};
	auditIntelligence: {
		artifacts: number;
		reportFindings: number;
		needsReview: number;
		researchNotes: number;
		severityCounts: Record<string, number>;
		provenanceCoverage: number;
		valueFlowCoverage: number;
		invariantCoverage: number;
		dimensionalCoverage: number;
		dimensionalMismatchCoverage: number;
		topImprovementSignals: Array<{ key: string; count: number }>;
		topDimensionalMismatchKinds: Array<{ kind: string; count: number }>;
		topInvariantKinds: Array<{ kind: string; count: number }>;
		recentTargets: Array<{
			projectId: string;
			projectTitle: string;
			jobId: string;
		}>;
	};
};

const intelligenceDir = process.env.BENCHMARK_INTELLIGENCE_DIR
	? resolve(process.env.BENCHMARK_INTELLIGENCE_DIR)
	: resolve(process.cwd(), "..", "..", "backend", "tmp", "audit-intelligence");

const resultsDir = resolve(process.cwd(), "benchmarks", "results");

function round(value: number): number {
	return Number(value.toFixed(3));
}

function increment(map: Map<string, number>, key: string, amount = 1) {
	map.set(key, (map.get(key) || 0) + amount);
}

function topEntries(map: Map<string, number>, limit = 10) {
	return Array.from(map.entries())
		.sort((a, b) => b[1] - a[1])
		.slice(0, limit);
}

async function collectJsonFiles(dir: string): Promise<string[]> {
	const entries = await readdir(dir, { withFileTypes: true });
	const files = await Promise.all(
		entries.map(async (entry) => {
			const fullPath = join(dir, entry.name);
			if (entry.isDirectory()) return collectJsonFiles(fullPath);
			if (entry.isFile() && entry.name.endsWith(".json")) return [fullPath];
			return [];
		}),
	);
	return files.flat();
}

async function buildAuditIntelligenceSummary(): Promise<
	BenchmarkScorecard["auditIntelligence"]
> {
	try {
		const files = await collectJsonFiles(intelligenceDir);
		const signalCounts = new Map<string, number>();
		const mismatchCounts = new Map<string, number>();
		const invariantCounts = new Map<string, number>();
		const recentTargets: Array<{
			projectId: string;
			projectTitle: string;
			jobId: string;
		}> = [];
		let artifacts = 0;
		let totalFindings = 0;
		let reportFindings = 0;
		let needsReview = 0;
		let researchNotes = 0;
		const severityCounts: Record<string, number> = {};
		let provenanceFacts = 0;
		let valueFlowFacts = 0;
		let invariantFacts = 0;
		let dimensionalFacts = 0;
		let dimensionalMismatchFacts = 0;

		for (const file of files) {
			if (file.endsWith("processed.json")) continue;
			const artifact = JSON.parse(await readFile(file, "utf8")) as AuditArtifact;
			artifacts += 1;
			recentTargets.push({
				projectId: String(artifact.projectId || "unknown"),
				projectTitle: String(artifact.projectTitle || `Project ${artifact.projectId || "unknown"}`),
				jobId: String(artifact.jobId || "unknown"),
			});

			for (const signal of artifact.improvementSignals || []) {
				increment(signalCounts, String(signal.key || "unknown"));
			}

			const structuredSummary = artifact.structuredSummary || {};
			const factCoverage = structuredSummary.factCoverage || {};
			const bucketCounts = structuredSummary.bucketCounts || {};
			const findingCount = Number(structuredSummary.totalFindings || 0);
			totalFindings += findingCount;
			reportFindings += Number(bucketCounts.report_finding || 0);
			needsReview += Number(bucketCounts.needs_review || 0);
			researchNotes += Number(bucketCounts.research_note || 0);
			for (const [severity, count] of Object.entries(structuredSummary.severityCounts || {})) {
				severityCounts[severity] = (severityCounts[severity] || 0) + Number(count || 0);
			}
			provenanceFacts += Number(factCoverage.provenance || 0);
			valueFlowFacts += Number(factCoverage.valueFlow || 0);
			invariantFacts += Number(factCoverage.invariants || 0);
			dimensionalFacts += Number(factCoverage.dimensional || 0);
			dimensionalMismatchFacts += Number(factCoverage.dimensionalMismatch || 0);

			const artifactKinds = new Set<string>();
			for (const sample of artifact.sampleFindings || []) {
				for (const kind of sample.dimensionalMismatchKinds || []) {
					artifactKinds.add(String(kind));
				}
			}
			for (const bucketSamples of Object.values(artifact.sampleFindingsByBucket || {})) {
				for (const sample of bucketSamples || []) {
					for (const kind of sample.dimensionalMismatchKinds || []) {
						artifactKinds.add(String(kind));
					}
				}
			}
			for (const kind of artifactKinds) {
				increment(mismatchCounts, kind);
			}
			const artifactInvariantKinds = new Set<string>();
			for (const sample of artifact.sampleFindings || []) {
				for (const kind of sample.invariantKinds || []) {
					artifactInvariantKinds.add(String(kind));
				}
			}
			for (const bucketSamples of Object.values(artifact.sampleFindingsByBucket || {})) {
				for (const sample of bucketSamples || []) {
					for (const kind of sample.invariantKinds || []) {
						artifactInvariantKinds.add(String(kind));
					}
				}
			}
			for (const kind of artifactInvariantKinds) {
				increment(invariantCounts, kind);
			}
		}

		return {
			artifacts,
			reportFindings,
			needsReview,
			researchNotes,
			severityCounts,
			provenanceCoverage: totalFindings === 0 ? 0 : round(provenanceFacts / totalFindings),
			valueFlowCoverage: totalFindings === 0 ? 0 : round(valueFlowFacts / totalFindings),
			invariantCoverage: totalFindings === 0 ? 0 : round(invariantFacts / totalFindings),
			dimensionalCoverage: totalFindings === 0 ? 0 : round(dimensionalFacts / totalFindings),
			dimensionalMismatchCoverage:
				totalFindings === 0 ? 0 : round(dimensionalMismatchFacts / totalFindings),
			topImprovementSignals: topEntries(signalCounts).map(([key, count]) => ({
				key,
				count,
			})),
			topDimensionalMismatchKinds: topEntries(mismatchCounts).map(([kind, count]) => ({
				kind,
				count,
			})),
			topInvariantKinds: topEntries(invariantCounts).map(([kind, count]) => ({
				kind,
				count,
			})),
			recentTargets: recentTargets.slice(-5).reverse(),
		};
	} catch {
		return {
			artifacts: 0,
			reportFindings: 0,
			needsReview: 0,
			researchNotes: 0,
			severityCounts: {},
			provenanceCoverage: 0,
			valueFlowCoverage: 0,
			invariantCoverage: 0,
			dimensionalCoverage: 0,
			dimensionalMismatchCoverage: 0,
			topImprovementSignals: [],
			topDimensionalMismatchKinds: [],
			topInvariantKinds: [],
			recentTargets: [],
		};
	}
}

async function main() {
	const slitherSummaries = TRIAGE_SLITHER_BENCHMARKS.map((fixture) =>
		evaluateSlitherBenchmark(fixture),
	);
	const slitherFixtureBreakdown = TRIAGE_SLITHER_BENCHMARKS.map(
		(fixture, index) => ({
			id: fixture.id,
			name: fixture.name,
			description: fixture.description,
			cases: fixture.expectations.length,
			transformAccuracy: slitherSummaries[index]?.transformAccuracy || 0,
			bucketAccuracy: slitherSummaries[index]?.bucketAccuracy || 0,
			verdictAccuracy: slitherSummaries[index]?.verdictAccuracy || 0,
			invariantAccuracy: slitherSummaries[index]?.invariantAccuracy || 0,
		}),
	);
	const slitherCases = slitherSummaries.reduce(
		(sum, summary) => sum + summary.total,
		0,
	);
	const slitherTransformMatches = slitherSummaries.reduce(
		(sum, summary) =>
			sum + summary.rows.filter((row) => row.transformMatched).length,
		0,
	);
	const slitherBucketMatches = slitherSummaries.reduce(
		(sum, summary) =>
			sum + summary.rows.filter((row) => row.bucketMatched).length,
		0,
	);
	const slitherVerdictMatches = slitherSummaries.reduce(
		(sum, summary) =>
			sum + summary.rows.filter((row) => row.verdictMatched).length,
		0,
	);
	const slitherInvariantMatches = slitherSummaries.reduce(
		(sum, summary) =>
			sum + summary.rows.filter((row) => row.invariantMatched).length,
		0,
	);

	const repoSummaries = TRIAGE_REPO_BENCHMARKS.map((fixture) =>
		evaluateRepoBenchmark(fixture),
	);
	const repoFixtureBreakdown = TRIAGE_REPO_BENCHMARKS.map((fixture, index) => ({
		id: fixture.id,
		name: fixture.name,
		description: fixture.description,
		cases: fixture.expectations.length,
		bucketAccuracy: repoSummaries[index]?.bucketAccuracy || 0,
		verdictAccuracy: repoSummaries[index]?.verdictAccuracy || 0,
		invariantAccuracy: repoSummaries[index]?.invariantAccuracy || 0,
	}));
	const repoCases = repoSummaries.reduce((sum, summary) => sum + summary.total, 0);
	const repoBucketMatches = repoSummaries.reduce(
		(sum, summary) => sum + summary.rows.filter((row) => row.bucketMatched).length,
		0,
	);
	const repoVerdictMatches = repoSummaries.reduce(
		(sum, summary) => sum + summary.rows.filter((row) => row.verdictMatched).length,
		0,
	);
	const repoInvariantMatches = repoSummaries.reduce(
		(sum, summary) => sum + summary.rows.filter((row) => row.invariantMatched).length,
		0,
	);

	const sourceSummaries = TRIAGE_SOURCE_BENCHMARKS.map((fixture) =>
		evaluateSourceBenchmark(fixture),
	);
	const sourceFixtureBreakdown = TRIAGE_SOURCE_BENCHMARKS.map((fixture, index) => ({
		id: fixture.id,
		name: fixture.name,
		description: fixture.description,
		cases: fixture.expectations.length,
		bucketAccuracy: sourceSummaries[index]?.bucketAccuracy || 0,
		verdictAccuracy: sourceSummaries[index]?.verdictAccuracy || 0,
		invariantAccuracy: sourceSummaries[index]?.invariantAccuracy || 0,
	}));
	const sourceCases = sourceSummaries.reduce(
		(sum, summary) => sum + summary.total,
		0,
	);
	const sourceBucketMatches = sourceSummaries.reduce(
		(sum, summary) =>
			sum + summary.rows.filter((row) => row.bucketMatched).length,
		0,
	);
	const sourceVerdictMatches = sourceSummaries.reduce(
		(sum, summary) =>
			sum + summary.rows.filter((row) => row.verdictMatched).length,
		0,
	);
	const sourceInvariantMatches = sourceSummaries.reduce(
		(sum, summary) =>
			sum + summary.rows.filter((row) => row.invariantMatched).length,
		0,
	);

	const auditorSummary = evaluateAuditorReviewSet(TRIAGE_AUDITOR_REVIEWSET);
	const focusAreaCounts = new Map<string, number>();
	for (const reviewCase of TRIAGE_AUDITOR_REVIEWSET) {
		for (const tag of reviewCase.tags || []) {
			increment(focusAreaCounts, tag);
		}
	}
	const auditIntelligence = await buildAuditIntelligenceSummary();

	const scorecard: BenchmarkScorecard = {
		generatedAt: new Date().toISOString(),
		slitherBenchmarks: {
			fixtures: slitherSummaries.length,
			cases: slitherCases,
			transformAccuracy:
				slitherCases === 0 ? 0 : round(slitherTransformMatches / slitherCases),
			bucketAccuracy:
				slitherCases === 0 ? 0 : round(slitherBucketMatches / slitherCases),
			verdictAccuracy:
				slitherCases === 0 ? 0 : round(slitherVerdictMatches / slitherCases),
			invariantAccuracy:
				slitherCases === 0 ? 0 : round(slitherInvariantMatches / slitherCases),
			fixtureBreakdown: slitherFixtureBreakdown,
		},
		repoBenchmarks: {
			fixtures: repoSummaries.length,
			cases: repoCases,
			bucketAccuracy:
				repoCases === 0 ? 0 : round(repoBucketMatches / repoCases),
			verdictAccuracy:
				repoCases === 0 ? 0 : round(repoVerdictMatches / repoCases),
			invariantAccuracy:
				repoCases === 0 ? 0 : round(repoInvariantMatches / repoCases),
			fixtureBreakdown: repoFixtureBreakdown,
		},
		sourceBenchmarks: {
			fixtures: sourceSummaries.length,
			cases: sourceCases,
			bucketAccuracy:
				sourceCases === 0 ? 0 : round(sourceBucketMatches / sourceCases),
			verdictAccuracy:
				sourceCases === 0 ? 0 : round(sourceVerdictMatches / sourceCases),
			invariantAccuracy:
				sourceCases === 0 ? 0 : round(sourceInvariantMatches / sourceCases),
			fixtureBreakdown: sourceFixtureBreakdown,
		},
		auditorReviewSet: {
			cases: auditorSummary.total,
			headlineAccuracy: auditorSummary.headlineAccuracy,
			bucketAccuracy: auditorSummary.bucketAccuracy,
			verdictAccuracy: auditorSummary.verdictAccuracy,
			invariantAccuracy: auditorSummary.invariantAccuracy,
			focusAreas: topEntries(focusAreaCounts, 6).map(([tag, count]) => ({
				tag,
				count,
			})),
			caseHighlights: TRIAGE_AUDITOR_REVIEWSET.slice(0, 6).map((item) => ({
				id: item.id,
				title: item.title,
				detector: item.detector,
				expectedBucket: item.expectedBucket,
				shouldHeadline: item.shouldHeadline,
			})),
		},
		auditIntelligence,
	};

	await mkdir(resultsDir, { recursive: true });
	const stamp = scorecard.generatedAt.replace(/[:.]/g, "-");
	const outputPath = join(resultsDir, `${stamp}.json`);
	await writeFile(outputPath, JSON.stringify(scorecard, null, 2), "utf8");

	console.log("=== SentinelAudit Benchmark Scorecard ===");
	console.log(`Generated: ${scorecard.generatedAt}`);
	console.log("");
	console.log("Slither benchmarks:");
	console.log(
		`- fixtures=${scorecard.slitherBenchmarks.fixtures} cases=${scorecard.slitherBenchmarks.cases} transform=${(scorecard.slitherBenchmarks.transformAccuracy * 100).toFixed(1)}% bucket=${(scorecard.slitherBenchmarks.bucketAccuracy * 100).toFixed(1)}% verdict=${(scorecard.slitherBenchmarks.verdictAccuracy * 100).toFixed(1)}% invariant=${(scorecard.slitherBenchmarks.invariantAccuracy * 100).toFixed(1)}%`,
	);
	console.log("Repo benchmarks:");
	console.log(
		`- fixtures=${scorecard.repoBenchmarks.fixtures} cases=${scorecard.repoBenchmarks.cases} bucket=${(scorecard.repoBenchmarks.bucketAccuracy * 100).toFixed(1)}% verdict=${(scorecard.repoBenchmarks.verdictAccuracy * 100).toFixed(1)}% invariant=${(scorecard.repoBenchmarks.invariantAccuracy * 100).toFixed(1)}%`,
	);
	console.log("Source benchmarks:");
	console.log(
		`- fixtures=${scorecard.sourceBenchmarks.fixtures} cases=${scorecard.sourceBenchmarks.cases} bucket=${(scorecard.sourceBenchmarks.bucketAccuracy * 100).toFixed(1)}% verdict=${(scorecard.sourceBenchmarks.verdictAccuracy * 100).toFixed(1)}% invariant=${(scorecard.sourceBenchmarks.invariantAccuracy * 100).toFixed(1)}%`,
	);
	console.log("Auditor review set:");
	console.log(
		`- cases=${scorecard.auditorReviewSet.cases} headline=${(scorecard.auditorReviewSet.headlineAccuracy * 100).toFixed(1)}% bucket=${(scorecard.auditorReviewSet.bucketAccuracy * 100).toFixed(1)}% verdict=${(scorecard.auditorReviewSet.verdictAccuracy * 100).toFixed(1)}% invariant=${(scorecard.auditorReviewSet.invariantAccuracy * 100).toFixed(1)}%`,
	);
	console.log("Audit intelligence:");
	console.log(
		`- artifacts=${auditIntelligence.artifacts} report=${auditIntelligence.reportFindings} review=${auditIntelligence.needsReview} research=${auditIntelligence.researchNotes}`,
	);
	console.log(
		`- provenance=${(auditIntelligence.provenanceCoverage * 100).toFixed(1)}% valueFlow=${(auditIntelligence.valueFlowCoverage * 100).toFixed(1)}% invariant=${(auditIntelligence.invariantCoverage * 100).toFixed(1)}% dimensional=${(auditIntelligence.dimensionalCoverage * 100).toFixed(1)}% mismatch=${(auditIntelligence.dimensionalMismatchCoverage * 100).toFixed(1)}%`,
	);
	console.log("");
	console.log(`Saved scorecard: ${outputPath}`);
}

main().catch((error) => {
	console.error("[benchmark-scorecard] Failed:", error);
	process.exitCode = 1;
});
