# Public Modules

The Slither runner contains both reusable compiler-analysis logic and
product-specific serving/runtime code.

The cleanest public surface is the helper layer exposed through:

- [package/public_api.py](D:/projects/audit/apps/api/slither/package/public_api.py)

## Public Runner Surface

This module intentionally exposes reusable helpers for:

- framework detection
- repo-aware dependency extraction
- remapping construction
- entrypoint version resolution
- compile preflight
- framework compile failure summarization
- Slither execution helpers

These are the parts most suitable for open publication because they capture the
repo-aware analysis method rather than product control-plane behavior.

## Keep Private

Do not publish these parts as-is:

- [package/server.py](D:/projects/audit/apps/api/slither/package/server.py)
- callback signing behavior in [package/utils.py](D:/projects/audit/apps/api/slither/package/utils.py)
- deployment scripts and local env files
- any runtime API-key handling or production callback assumptions

## Extraction Path

Short term:

- keep the runner intact
- document and publish the helper layer first

Later:

- extract the reusable compile/scan helpers into a dedicated package such as
  `@sentinelaudit/slither-runner-core` or a standalone Python package

