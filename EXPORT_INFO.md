# SentinelAudit Public Export

Generated from private monorepo commit: `0f172f2`

License: Apache-2.0 (see `LICENSE`). The moat is the labeled data and hosted
infrastructure, not the method — so the method is published permissively.

This folder contains only the approved public-first surfaces of SentinelAudit.

Included:
- LLM triage harness public surface (method + illustrative seed fixtures only)
- Slither runner core helper surface
- release and contribution docs

Excluded:
- backend auth, billing, and control-plane code
- customer data paths
- internal audit-intelligence artifacts (the real labeled goldset/reviewset —
  `src/private/`, `drops/` — stays private; only synthetic fixtures ship here)
- local env and deployment secrets
