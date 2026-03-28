import re
from typing import List, Optional, Tuple

from schemas import FileIn

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


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


def detect_openzeppelin_version(pragmas: List[str]) -> str:
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
        return detect_openzeppelin_version(extract_pragmas_from_files(files))
    return "latest"
