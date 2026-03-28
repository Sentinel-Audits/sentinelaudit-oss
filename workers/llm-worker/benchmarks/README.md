# Benchmarking

SentinelAudit benchmarking is split into two evidence layers that should not be
blurred together:

- public benchmark corpus
- production telemetry

## Public Benchmark Corpus

The public benchmark corpus is intended to be inspectable and repeatable. It is
built from:

- named repo benchmark fixtures in
  [src/lib/triage-repo-benchmarks.ts](/D:/projects/audit/apps/workers/llm-worker/src/lib/triage-repo-benchmarks.ts)
- auditor-aligned review cases in
  [src/lib/triage-auditor-reviewset.ts](/D:/projects/audit/apps/workers/llm-worker/src/lib/triage-auditor-reviewset.ts)

These fixtures are designed to answer concrete questions such as:

- does Sentinel suppress dependency noise correctly?
- does it keep dangerous public value-transfer paths as headline candidates?
- does it avoid over-promoting signer-gated or role-gated flows?
- does it treat upgradeability and low-level-call issues conservatively when
  context is incomplete?

## Production Telemetry

Production telemetry is useful for directional quality measurement, but it is
not a public benchmark corpus. It is derived from downloaded audit-intelligence
artifacts and is anonymized by default in public materials.

Telemetry helps answer questions like:

- how much provenance coverage do recent audits have?
- how much value-flow coverage is being extracted?
- are dimensional observations showing up on accounting-heavy repos?
- which improvement signals are recurring across recent runs?

## Scorecards

Generate a scorecard:

```bash
bun run bench:scorecard
```

Generate a shareable scorecard snapshot:

```bash
bun run bench:share
```

The output is written to:

- `benchmarks/results`
- `benchmarks/share`

## Public Reporting Guidance

Public benchmark updates should emphasize:

- named corpus coverage
- benchmark methodology
- trendlines over time
- anonymized production telemetry

Avoid presenting internal telemetry alone as if it were a public benchmark
leaderboard.
