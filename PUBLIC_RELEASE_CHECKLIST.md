# Public Release Checklist

Use this before publishing any SentinelAudit code publicly.

## 1. Run the local release audit

From [D:/projects/audit/apps](D:/projects/audit/apps):

```bash
bun run audit:public-surface
```

Do not publish until blockers are removed, excluded, or intentionally extracted.

## 2. Confirm the release surface

Current public-first surfaces:

- [workers/llm-worker/src/public/triage.ts](D:/projects/audit/apps/workers/llm-worker/src/public/triage.ts)
- [api/slither/package/public_api.py](D:/projects/audit/apps/api/slither/package/public_api.py)
- validation-runner helpers documented in [OSS_MODULES.md](D:/projects/audit/apps/OSS_MODULES.md)

## 3. Remove or exclude private materials

Keep these out of any public release:

- env files
- local worker vars
- internal audit-intelligence artifacts
- temp working files
- customer-specific billing or auth internals

## 4. Verify docs

Make sure these docs are present and accurate:

- [README.md](D:/projects/audit/apps/README.md)
- [PUBLIC_RELEASE_BOUNDARY.md](D:/projects/audit/apps/docs/PUBLIC_RELEASE_BOUNDARY.md)
- [OSS_MODULES.md](D:/projects/audit/apps/OSS_MODULES.md)
- [CONTRIBUTING.md](D:/projects/audit/apps/CONTRIBUTING.md)
- [SECURITY.md](D:/projects/audit/apps/SECURITY.md)

## 5. Verify product safety

Public release work must not break:

- backend auth and billing
- report generation
- runner callbacks
- worker tokens
- customer history or stored results

If a change touches those paths, treat it as private-product work, not open-source prep.

## 6. Prefer extraction over exposure

If a module is valuable but mixed with product logic:

- extract it
- add a stable public entrypoint
- document it
- test it

Do not publish product internals just because they sit next to reusable code.
