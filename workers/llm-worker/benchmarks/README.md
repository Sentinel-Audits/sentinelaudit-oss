# Benchmarking

SentinelAudit benchmarking is split into two evidence layers:

- public benchmark corpus
- production telemetry

These should be presented together, but not confused with each other.

## Public Benchmark Corpus

The public benchmark corpus is meant to be inspectable and repeatable. It is
built from:

- named repo benchmark fixtures in
  [src/lib/triage-repo-benchmarks.ts](/D:/projects/audit/apps/workers/llm-worker/src/lib/triage-repo-benchmarks.ts)
- auditor-aligned review cases in
  [src/lib/triage-auditor-reviewset.ts](/D:/projects/audit/apps/workers/llm-worker/src/lib/triage-auditor-reviewset.ts)

This layer answers questions like:

- does Sentinel suppress dependency-heavy noise?
- does it preserve real public value-transfer issues as headline candidates?
- does it keep context-heavy upgrade or low-level-call findings in review lanes?
- does it treat signer-gated or privileged flows conservatively?

## Production Telemetry

Production telemetry comes from downloaded audit-intelligence artifacts. It is
useful for directional quality measurement, but it is not the same thing as a
public benchmark corpus.

This layer helps answer questions like:

- how much provenance coverage do recent audits have?
- how much value-flow coverage is being extracted?
- are dimensional observations showing up on accounting-heavy repos?
- which improvement signals are recurring across recent runs?

Public materials should anonymize this telemetry by default unless repo names
are explicitly safe to disclose.

## Scorecards

Generate a scorecard:

```bash
bun run bench:scorecard
```

Generate a shareable benchmark card:

```bash
bun run bench:share
```

Outputs are written to:

- `benchmarks/results`
- `benchmarks/share`

## Reporting Guidance

The most credible public benchmark updates emphasize:

- named corpus coverage
- clear methodology
- output mix such as report, review, and research lanes
- longitudinal trendlines
- anonymized production telemetry

Avoid presenting internal telemetry alone as if it were a public benchmark
leaderboard.
