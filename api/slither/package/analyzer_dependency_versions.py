import re
from typing import List, Optional, Tuple

from schemas import FileIn

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
IMPORT_RE = re.compile(r'import\s+(?:[^"\']*\s+from\s+)?["\']([^"\']+)["\']')

# Files / paths that were REMOVED or moved in OpenZeppelin v5.x.
# If a project imports any of these, it must be on OZ 4.x.
# Source: https://docs.openzeppelin.com/contracts/5.x/upgrade-Counters
OZ_V4_ONLY_IMPORTS = (
    "@openzeppelin/contracts/utils/Counters.sol",
    "@openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol",
    "@openzeppelin/contracts/finance/PaymentSplitter.sol",
    "@openzeppelin/contracts/security/Pausable.sol",  # moved to /utils/Pausable.sol in v5
    "@openzeppelin/contracts/security/ReentrancyGuard.sol",  # moved to /utils/ReentrancyGuard.sol in v5
    "@openzeppelin/contracts/governance/utils/IVotes.sol",  # moved
    "@openzeppelin/contracts/access/AccessControlCrossChain.sol",  # removed
    "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol",  # renamed
    "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol",  # renamed
    "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol",
    "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol",
    "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol",
    "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol",
)


def _is_solidity_file(path: Optional[str]) -> bool:
    normalized = (path or "").replace("\\", "/").lower()
    return normalized.endswith(".sol")


def extract_pragmas_from_files(files: List[FileIn]) -> List[str]:
    pragmas: List[str] = []
    for file in files:
        if not _is_solidity_file(file.path):
            continue
        for match in PRAGMA_RE.findall(file.content or ""):
            pragmas.append(match.strip())
    return pragmas


def has_oz_v4_only_imports(files: List[FileIn]) -> bool:
    """
    Returns True if any Solidity file imports an OpenZeppelin path that was
    removed or relocated in v5.x. In that case the project MUST be on OZ 4.x
    regardless of pragma.
    """
    for file in files:
        if not _is_solidity_file(file.path):
            continue
        for imp in IMPORT_RE.findall(file.content or ""):
            normalized = imp.strip()
            for v4_path in OZ_V4_ONLY_IMPORTS:
                if normalized == v4_path or normalized.endswith(v4_path):
                    return True
    return False


def detect_openzeppelin_version(
    pragmas: List[str],
    files: Optional[List[FileIn]] = None,
) -> str:
    # Hard override: if the source uses any OZ 4.x-only API, force 4.x
    # regardless of what the Solidity pragma says.
    if files is not None and has_oz_v4_only_imports(files):
        return "4.9.6"

    versions: List[Tuple[int, int, int]] = []
    for pragma in pragmas:
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", pragma)
        if match:
            versions.append(
                (int(match.group(1)), int(match.group(2)), int(match.group(3)))
            )

    if not versions:
        return "4.9.6"

    highest = max(versions)
    if highest >= (0, 8, 20):
        return "5.0.2"
    if highest >= (0, 8, 8):
        return "4.9.6"
    if highest >= (0, 8, 0):
        return "4.8.0"
    return "4.8.0"


def infer_default_dependency_version(package_name: str, files: List[FileIn]) -> str:
    if package_name in {
        "@openzeppelin/contracts",
        "@openzeppelin/contracts-upgradeable",
    }:
        return detect_openzeppelin_version(extract_pragmas_from_files(files), files)
    return "latest"
