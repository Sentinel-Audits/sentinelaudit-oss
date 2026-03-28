# OSS Modules

This file maps the parts of SentinelAudit that are the best candidates for
selective open-sourcing without exposing private product operations.

## Public-First Modules

### 1. LLM Triage Harness

Location:

- [workers/llm-worker/src/public/triage.ts](D:/projects/audit/apps/workers/llm-worker/src/public/triage.ts)

Includes:

- deterministic triage helpers
- bucket classification helpers
- exploitability-story fallback helpers
- gold set and evaluation utilities
- repo and auditor review fixtures

### 2. Slither Runner Core Helpers

Location:

- [api/slither/package/public_api.py](D:/projects/audit/apps/api/slither/package/public_api.py)

Includes:

- framework detection
- dependency extraction
- remapping construction
- entrypoint version resolution
- compile preflight helpers
- Slither execution helpers

### 3. Validation Runner Helpers

Location:

- [api/echidna/package/server.py](D:/projects/audit/apps/api/echidna/package/server.py)

Includes:

- safe workspace path handling
- workspace materialization helpers
- dependency installation helpers
- validation workspace preparation

## Private Product Layers

These should remain private unless explicitly extracted and sanitized:

- backend auth and billing logic
- customer/subscription state handling
- GitHub app credential flows
- internal audit-intelligence artifacts
- private report history and control-plane orchestration

## Release Rule

Open-source the reusable method and tooling layers first.

Keep product operating layers private until they are intentionally redesigned
for public consumption.
