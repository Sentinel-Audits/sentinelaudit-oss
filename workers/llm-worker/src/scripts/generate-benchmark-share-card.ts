import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

type BenchmarkScorecard = {
	generatedAt: string;
	repoBenchmarks: {
		fixtures: number;
		cases: number;
		bucketAccuracy: number;
		verdictAccuracy: number;
		fixtureBreakdown: Array<{
			id: string;
			name: string;
			description: string;
			cases: number;
			bucketAccuracy: number;
			verdictAccuracy: number;
		}>;
	};
	auditorReviewSet: {
		cases: number;
		headlineAccuracy: number;
		bucketAccuracy: number;
		verdictAccuracy: number;
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
		provenanceCoverage: number;
		valueFlowCoverage: number;
		dimensionalCoverage: number;
		dimensionalMismatchCoverage: number;
		topImprovementSignals: Array<{ key: string; count: number }>;
		topDimensionalMismatchKinds: Array<{ kind: string; count: number }>;
		recentTargets: Array<{
			projectId: string;
			projectTitle: string;
			jobId: string;
		}>;
	};
};

const resultsDir = resolve(process.cwd(), "benchmarks", "results");
const shareDir = resolve(process.cwd(), "benchmarks", "share");

async function getLatestScorecardPath() {
	const entries = await readdir(resultsDir, { withFileTypes: true });
	const files = entries
		.filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
		.map((entry) => entry.name)
		.sort()
		.reverse();
	if (files.length === 0) {
		throw new Error(`No benchmark scorecards found in ${resultsDir}`);
	}
	return join(resultsDir, files[0]);
}

function pct(value: number) {
	return `${(value * 100).toFixed(1)}%`;
}

function escapeXml(value: string) {
	return String(value)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&apos;");
}

function renderMetricCard(
	x: number,
	y: number,
	label: string,
	value: string,
	subvalue: string,
	fill: string,
) {
	return `
		<g transform="translate(${x} ${y})">
			<rect width="340" height="122" rx="10" fill="${fill}" stroke="#27272A" />
			<text x="22" y="34" fill="#A1A1AA" font-size="16" font-family="Inter, Arial, sans-serif" font-weight="700">${escapeXml(label.toUpperCase())}</text>
			<text x="22" y="76" fill="#FAFAFA" font-size="40" font-family="Inter, Arial, sans-serif" font-weight="800">${escapeXml(value)}</text>
			<text x="22" y="101" fill="#D4D4D8" font-size="17" font-family="Inter, Arial, sans-serif">${escapeXml(subvalue)}</text>
		</g>
	`;
}

function renderTextLines(
	x: number,
	startY: number,
	lines: string[],
	fontSize: number,
	lineHeight: number,
	color: string,
	fontWeight = "400",
) {
	return lines
		.map(
			(line, index) => `<text x="${x}" y="${startY + index * lineHeight}" fill="${color}" font-size="${fontSize}" font-family="Inter, Arial, sans-serif" font-weight="${fontWeight}">${escapeXml(line)}</text>`,
		)
		.join("\n");
}

function buildSvg(scorecard: BenchmarkScorecard) {
	const topSignal =
		scorecard.auditIntelligence.topImprovementSignals[0]?.key || "none";
	const topMismatch =
		scorecard.auditIntelligence.topDimensionalMismatchKinds[0]?.kind || "none";
	const corpusLines = scorecard.repoBenchmarks.fixtureBreakdown
		.slice(0, 4)
		.map((fixture) => `${fixture.name} (${fixture.cases} cases)`);
	const focusLines = scorecard.auditorReviewSet.focusAreas
		.slice(0, 4)
		.map((area) => `${area.tag} (${area.count})`);
	const methodologyLines = [
		"Evidence layers",
		"1. curated repo benchmark fixtures",
		"2. auditor-aligned reviewset expectations",
		"3. anonymized production telemetry",
	];
	const telemetryLines = [
		`${scorecard.auditIntelligence.artifacts} local audit artifacts`,
		`${scorecard.auditIntelligence.reportFindings} report findings / ${scorecard.auditIntelligence.needsReview} review findings`,
		`top signal: ${topSignal}`,
		`top mismatch: ${topMismatch}`,
	];

	return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="1600" height="900" viewBox="0 0 1600 900" fill="none" xmlns="http://www.w3.org/2000/svg">
	<rect width="1600" height="900" fill="#000000"/>
	<line x1="80" y1="84" x2="1520" y2="84" stroke="#27272A"/>
	<line x1="80" y1="822" x2="1520" y2="822" stroke="#27272A"/>
	<text x="80" y="70" fill="#FAFAFA" font-size="18" font-family="Inter, Arial, sans-serif" font-weight="700">SENTINELAUDIT BENCHMARK SNAPSHOT</text>
	<text x="80" y="155" fill="#FAFAFA" font-size="60" font-family="Georgia, Times New Roman, serif" font-weight="700">Security Workflow Benchmarking</text>
	<text x="80" y="198" fill="#A1A1AA" font-size="22" font-family="Inter, Arial, sans-serif">Generated ${escapeXml(scorecard.generatedAt.slice(0, 10))} from deterministic benchmark suites and local audit telemetry.</text>

	${renderMetricCard(
		80,
		248,
		"Repo Benchmarks",
		pct(scorecard.repoBenchmarks.bucketAccuracy),
		`${scorecard.repoBenchmarks.fixtures} fixtures - ${scorecard.repoBenchmarks.cases} cases`,
		"#0A0A0A",
	)}
	${renderMetricCard(
		450,
		248,
		"Auditor Review Set",
		pct(scorecard.auditorReviewSet.headlineAccuracy),
		`${scorecard.auditorReviewSet.cases} reviewed cases`,
		"#0A0A0A",
	)}
	${renderMetricCard(
		820,
		248,
		"Provenance Coverage",
		pct(scorecard.auditIntelligence.provenanceCoverage),
		`${scorecard.auditIntelligence.artifacts} local artifacts`,
		"#0A0A0A",
	)}
	${renderMetricCard(
		1190,
		248,
		"Value-Flow Coverage",
		pct(scorecard.auditIntelligence.valueFlowCoverage),
		`${scorecard.auditIntelligence.reportFindings} report - ${scorecard.auditIntelligence.needsReview} review`,
		"#0A0A0A",
	)}

	<g transform="translate(80 430)">
		<rect width="700" height="338" rx="14" fill="#0A0A0A" stroke="#27272A" />
		<text x="30" y="44" fill="#FAFAFA" font-size="28" font-family="Inter, Arial, sans-serif" font-weight="800">Public benchmark corpus</text>
		<text x="30" y="77" fill="#A1A1AA" font-size="19" font-family="Inter, Arial, sans-serif">Named fixtures and review focus areas that can be inspected directly.</text>
		${renderTextLines(30, 130, corpusLines, 21, 34, "#FAFAFA", "600")}
		<text x="30" y="272" fill="#A1A1AA" font-size="18" font-family="Inter, Arial, sans-serif" font-weight="700">Auditor review focus</text>
		${renderTextLines(30, 304, focusLines, 20, 30, "#D4D4D8", "400")}
	</g>

	<g transform="translate(820 430)">
		<rect width="700" height="338" rx="14" fill="#0A0A0A" stroke="#27272A" />
		<text x="34" y="44" fill="#FAFAFA" font-size="28" font-family="Inter, Arial, sans-serif" font-weight="800">Telemetry and method</text>
		${renderTextLines(34, 92, telemetryLines, 20, 30, "#FAFAFA", "500")}
		<text x="34" y="238" fill="#A1A1AA" font-size="18" font-family="Inter, Arial, sans-serif" font-weight="700">Methodology</text>
		${renderTextLines(34, 272, methodologyLines, 20, 28, "#D4D4D8")}
	</g>

	<text x="80" y="852" fill="#71717A" font-size="18" font-family="Inter, Arial, sans-serif">Public benchmark corpus is inspectable. Production telemetry is anonymized by default.</text>
</svg>`;
}

function buildMarkdown(scorecard: BenchmarkScorecard) {
	const topSignal =
		scorecard.auditIntelligence.topImprovementSignals[0]?.key || "none";
	const topMismatch =
		scorecard.auditIntelligence.topDimensionalMismatchKinds[0]?.kind || "none";

	return `# SentinelAudit Benchmark Snapshot

- Generated: ${scorecard.generatedAt}
- Repo benchmarks: ${pct(scorecard.repoBenchmarks.bucketAccuracy)} bucket accuracy across ${scorecard.repoBenchmarks.fixtures} fixtures / ${scorecard.repoBenchmarks.cases} cases
- Auditor review set: ${pct(scorecard.auditorReviewSet.headlineAccuracy)} headline accuracy across ${scorecard.auditorReviewSet.cases} cases
- Audit intelligence artifacts: ${scorecard.auditIntelligence.artifacts}
- Provenance coverage: ${pct(scorecard.auditIntelligence.provenanceCoverage)}
- Value-flow coverage: ${pct(scorecard.auditIntelligence.valueFlowCoverage)}
- Dimensional coverage: ${pct(scorecard.auditIntelligence.dimensionalCoverage)}
- Dimensional mismatch coverage: ${pct(scorecard.auditIntelligence.dimensionalMismatchCoverage)}
- Top improvement signal: ${topSignal}
- Top mismatch kind: ${topMismatch}

Public benchmark corpus:
${scorecard.repoBenchmarks.fixtureBreakdown
	.slice(0, 6)
	.map((fixture) => `- ${fixture.name}: ${fixture.cases} cases`)
	.join("\n")}

Auditor review focus:
${scorecard.auditorReviewSet.focusAreas
	.slice(0, 6)
	.map((area) => `- ${area.tag}: ${area.count}`)
	.join("\n")}

Recent audited targets (local telemetry):
${scorecard.auditIntelligence.recentTargets.length > 0
	? scorecard.auditIntelligence.recentTargets
			.slice(0, 5)
			.map(
				(target) =>
					`- ${target.projectTitle} (${target.projectId}) – job ${target.jobId}`,
			)
			.join("\n")
	: "- none"}

Methodology:
- curated repo benchmark fixtures
- auditor-aligned reviewset expectations
- anonymized audit-intelligence telemetry from real audit runs
`;
}

async function main() {
	const latestScorecardPath = await getLatestScorecardPath();
	const scorecard = JSON.parse(
		await readFile(latestScorecardPath, "utf8"),
	) as BenchmarkScorecard;

	await mkdir(shareDir, { recursive: true });
	const stem = latestScorecardPath.split("\\").pop()?.replace(/\.json$/i, "") || "latest";
	const svgPath = join(shareDir, `${stem}.svg`);
	const mdPath = join(shareDir, `${stem}.md`);

	await writeFile(svgPath, buildSvg(scorecard), "utf8");
	await writeFile(mdPath, buildMarkdown(scorecard), "utf8");

	console.log("=== SentinelAudit Benchmark Share Assets ===");
	console.log(`Source scorecard: ${latestScorecardPath}`);
	console.log(`SVG card: ${svgPath}`);
	console.log(`Markdown summary: ${mdPath}`);
}

main().catch((error) => {
	console.error("[benchmark-share-card] Failed:", error);
	process.exitCode = 1;
});
