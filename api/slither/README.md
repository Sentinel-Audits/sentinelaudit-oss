# Slither Runner

FastAPI service that runs Slither against uploaded Solidity workspaces.

## What Is Special About This Runner

- Uses Slither for detector output
- Uses `crytic-compile` automatically for framework repos
- Supports:
  - Foundry
  - Hardhat
  - Truffle
  - Brownie
- Includes Foundry tooling in the container so Foundry repos can execute `forge`
- Falls back to the manual pragma/remapping path for loose Solidity uploads

## Public-First Surface

The safest public slice in this runner is the reusable compile-and-analysis
helper layer.

See:

- [PUBLIC_MODULES.md](D:/projects/audit/apps/api/slither/PUBLIC_MODULES.md)
- [package/public_api.py](D:/projects/audit/apps/api/slither/package/public_api.py)

This gives SentinelAudit a stable public entry point for:

- framework detection
- dependency extraction
- remapping construction
- compile preflight helpers
- Slither execution helpers

## Accepted Workspace Inputs

The runner works best when the uploaded workspace preserves repo structure.

Supported file types include:

- `.sol`
- `package.json`
- `foundry.toml`
- `remappings.txt`
- `hardhat.config.ts|js|mjs|cjs`
- `truffle-config.ts|js|cjs`
- `brownie-config.yml|yaml|json`
- `.gitmodules`
- lockfiles such as `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb`

Resolver/config files help compilation but are not scan targets.

For GitHub-connected audits, the normal expectation is:

- the frontend/backend import flow expands the selected Solidity entrypoints into the workspace the runner needs
- users should not need to manually upload vendored OpenZeppelin or Foundry support files one by one
- the runner still requires those files to be present in the final workspace it receives

## Runtime Behavior

### Framework Mode

If the workspace looks like a real repo, the runner uses `crytic-compile`.

Examples:

- Foundry repo with `foundry.toml`
- Hardhat repo with `hardhat.config.*`
- Truffle repo with `truffle-config.*`

This is the preferred path for GitHub imports.

The runner also performs repo-aware dependency handling for framework workspaces:

- package-manager install from the selected manifest
- fallback install for Solidity-needed packages that were inferred from imports
- Solidity-only dependency inference, so JS/runtime imports do not leak into audit installs
- exact OpenZeppelin version pinning by pragma bucket instead of floating semver ranges
- alias/remapping handling for Foundry-style import prefixes
- materialization of vendored `lib/...` paths used by framework compilers

### Loose File Mode

If the workspace is just a few Solidity files without framework metadata, the runner uses the existing manual compiler-resolution path.

## Endpoints

### `GET /health`

Health check.

### `POST /run/slither`

Runs the full analysis job for one workspace.

### `POST /compile`

Compile-only preflight. Useful for diagnosing repo resolution before a full run.
When a `callbackURL` is provided, the preflight path now also emits
`INSTALLING_DEPENDENCIES` progress so the main product UI can reflect framework
workspace preparation instead of looking frozen before scan start.

## Request Shape

The runner expects:

```json
{
  "jobId": "job-123",
  "projectId": "49",
  "entrypoints": ["src/Token.sol"],
  "files": [
    { "path": "src/Token.sol", "content": "..." }
  ]
}
```

## Environment

- `SLITHER_API_KEY`
- optional logging settings

## Deployment Notes

The container includes:

- Slither
- `crytic-compile`
- `solc-select`
- preinstalled `solc` versions
- Foundry (`forge`)

If Foundry repos fail with `Cannot execute forge`, the deployed image is stale and the service needs redeploying with the current [Dockerfile](./Dockerfile).

## Practical Guidance

- For repo-based audits, upload or import the real repo structure.
- For GitHub imports, selecting one main `.sol` file should usually be enough because Sentinel expands local dependencies, resolver files, and required vendored library roots automatically.
- `crytic-compile` improves build fidelity, but it still cannot compile files that are missing from the workspace.
