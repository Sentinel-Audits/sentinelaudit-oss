# Public Release Boundary

This document defines what SentinelAudit can safely publish now without
breaking the product flow or exposing internal operating details.

## Public-First Areas

These are the safest candidates to open first:

- `workers/llm-worker/src/lib/*`
  - triage logic
  - evaluator harnesses
  - benchmark/reviewset structure
- `api/slither/*`
  - runner scaffolding
  - compile/scan orchestration patterns
- `api/echidna/*`
  - validation runner scaffolding
- `shared/*`
  - framework-neutral utilities that do not depend on auth, billing, or
    customer data
- selected documentation explaining architecture, audit philosophy, and
  validation model

These areas are already close to "tooling" or "method" value rather than
private product operations.

## Keep Private

These areas should remain private unless they are first extracted and sanitized:

- `backend/src/lib/auth.ts`
- `backend/src/lib/polar.ts`
- `backend/src/routes/auth.ts`
- `backend/src/routes/projects-github*.ts`
- `backend/src/routes/jobs*.ts`
- `backend/src/routes/projects-results-routes.ts`
- `backend/tmp/*`
- `web/polar-config.json`
- `web/app/settings/*`
- internal evaluation exports and any user-derived audit intelligence artifacts

Why:

- auth and billing flows are product-sensitive
- GitHub app integration depends on private app credentials
- job orchestration contains internal control-plane details
- audit-intelligence artifacts are derived from real user activity and internal
  quality review loops

## Safe Public Narrative

Publicly, SentinelAudit should be described as:

- an AI-assisted smart contract security workflow
- built around deterministic scanning, structured triage, validation, and
  re-audit
- focused on reducing dependency noise and improving exploitability-oriented
  reasoning

It should not publicly expose:

- customer-specific billing rules
- internal evaluation exports
- private runner auth strategy
- secret names or production topology assumptions beyond what is necessary

## Recommended Near-Term Structure

Keep the product monorepo intact, but publish in phases.

### Phase 1: Public Method + Tooling

Publish:

- LLM triage harnesses
- selected runner scaffolding
- architecture docs
- evaluation methodology

Keep private:

- backend API
- billing/auth
- user report history
- private intelligence export flows

### Phase 2: Extract Shared OSS Packages

When stable, extract into standalone packages or a public mirror:

- `@sentinelaudit/triage-harness`
- `@sentinelaudit/slither-normalizer`
- `@sentinelaudit/validation-runner-contracts`

This reduces the chance that product-only code leaks into the public surface.

### Phase 3: Public Interface Hardening

Before any broader publication:

- remove temp files
- remove env files
- strip private notes and internal docs
- run `bun run audit:public-surface`
- confirm README, SECURITY, and CONTRIBUTING docs are present

## Release Principle

Open-source the method and reusable tooling first.

Keep the operating system of the product private until the public modules are
clean, stable, and intentionally extracted.
