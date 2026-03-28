# Public Modules

This worker contains both product-specific logic and reusable audit-triage
tooling.

The safest public surface to expose first is the triage harness layer.

## Public Triage Surface

Use:

- [src/public/triage.ts](D:/projects/audit/apps/workers/llm-worker/src/public/triage.ts)

This barrel intentionally re-exports:

- deterministic triage helpers
- structured bucket helpers
- exploitability-story fallback helpers
- triage evaluation utilities
- seed gold set
- repo benchmarks
- auditor review set

## Why This Surface

These modules are method-heavy and reusable:

- they help evaluate detector triage quality
- they capture benchmark and review logic
- they do not require product auth, billing, or customer data

## Keep Private Inside This Worker

Do not publish these parts as-is:

- request handlers in `src/index.ts`
- RAG/OpenAI/Gemini service bindings
- fix generation prompts that encode product-specific behavior
- any path that depends on runtime secrets or production topology

## Extraction Path

Short term:

- keep this worker intact
- publish only the triage barrel and its supporting docs/tests

Later:

- move this surface into a dedicated package such as
  `@sentinelaudit/triage-harness`

