# Contributing

Thanks for your interest in SentinelAudit.

At this stage, the project is being opened selectively. Contributions are most
useful in the public tooling and research-oriented areas of the codebase:

- triage harnesses
- evaluation fixtures
- validation runner improvements
- documentation clarity

## Ground Rules

- prefer deterministic behavior over cleverness
- do not weaken finding truthfulness for nicer demos
- keep dependency noise out of first-party risk paths
- preserve the distinction between `report_finding`, `needs_review`, and
  `research_note`

## Before Opening a PR

1. Run the relevant local checks.
2. Keep changes scoped.
3. Avoid committing environment files, secrets, or generated temp artifacts.
4. If a change touches product-only flows such as billing, auth, or customer
   exports, open an issue first rather than assuming it belongs in the public
   surface.

## Local Checks

From `D:/projects/audit/apps`:

```bash
bun run check:web
bun run check:backend
bun run check:llm
```

For triage-specific work:

```bash
cd workers/llm-worker
bun run test:triage
```

## What Not To Submit Publicly

Please do not submit changes that include:

- real customer data
- internal audit-intelligence exports
- env files or tokens
- private billing configuration
- temporary working files

If you are unsure whether something belongs in the public surface, assume it
does not and ask first.
