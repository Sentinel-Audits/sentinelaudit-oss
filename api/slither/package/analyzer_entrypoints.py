import json
import os
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from semantic_version import NpmSpec, Version

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
IMPORT_RE = re.compile(r'import\s+(?:[^"\']*\s+from\s+)?["\']([^"\']+)["\']')

SUPPORTED_VERSIONS = [
    Version("0.8.30"),
    Version("0.8.29"),
    Version("0.8.28"),
    Version("0.8.27"),
    Version("0.8.26"),
    Version("0.8.25"),
    Version("0.8.24"),
    Version("0.8.23"),
    Version("0.8.22"),
    Version("0.8.21"),
    Version("0.8.20"),
    Version("0.8.19"),
    Version("0.8.18"),
    Version("0.8.17"),
    Version("0.8.16"),
    Version("0.8.15"),
    Version("0.8.14"),
    Version("0.8.13"),
    Version("0.8.12"),
    Version("0.8.11"),
    Version("0.8.10"),
    Version("0.8.9"),
    Version("0.8.8"),
    Version("0.8.7"),
    Version("0.8.6"),
    Version("0.8.5"),
    Version("0.8.4"),
    Version("0.8.3"),
    Version("0.8.2"),
    Version("0.8.1"),
    Version("0.8.0"),
    Version("0.7.6"),
    Version("0.7.5"),
    Version("0.7.4"),
    Version("0.7.0"),
    Version("0.6.12"),
    Version("0.6.0"),
    Version("0.5.17"),
    Version("0.5.16"),
    Version("0.5.0"),
    Version("0.4.26"),
    Version("0.4.11"),
]


def find_content(path: str, file_map: Dict[str, str], td: str, logger) -> Optional[str]:
    path = os.path.normpath(path).replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]

    if path in file_map:
        return file_map[path]

    for key, value in file_map.items():
        if key == path:
            return value
        if key == f"./{path}":
            return value
        if key.endswith(f"/{path}"):
            logger.info(f"Fuzzy match found for '{path}': using '{key}'")
            return value

    disk_path = os.path.join(td, path)
    if os.path.exists(disk_path) and os.path.isfile(disk_path):
        try:
            with open(disk_path, "r", encoding="utf-8", errors="ignore") as handle:
                return handle.read()
        except Exception:
            return None

    return None


def resolve_import_to_disk(td: str, importer_path: str, imp: str) -> Optional[str]:
    importer_path = os.path.normpath(importer_path).replace("\\", "/")

    if imp.startswith("./") or imp.startswith("../"):
        base_dir = os.path.dirname(importer_path)
        return os.path.normpath(os.path.join(base_dir, imp)).replace("\\", "/")

    if imp.startswith("@"):
        return os.path.normpath(os.path.join("node_modules", imp)).replace("\\", "/")

    if imp.startswith("forge-std/"):
        candidate_src = os.path.normpath(
            os.path.join("node_modules", "forge-std", "src", imp[len("forge-std/") :])
        ).replace("\\", "/")
        if os.path.exists(os.path.join(td, candidate_src)):
            return candidate_src
        return os.path.normpath(os.path.join("node_modules", imp)).replace("\\", "/")

    return os.path.normpath(os.path.join("node_modules", imp)).replace("\\", "/")


def get_transitive_dependencies(
    entrypoint_path: str,
    td: str,
    file_map: Dict[str, str],
    logger,
) -> Set[str]:
    deps: Set[str] = set()
    stack = [entrypoint_path]
    visited: Set[str] = set()

    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        deps.add(current)

        content = find_content(current, file_map, td, logger)
        if not content:
            continue

        for imp in IMPORT_RE.findall(content):
            resolved = resolve_import_to_disk(td, current, imp)
            if resolved:
                stack.append(resolved)

    return deps


def collect_entrypoint_pragmas(
    entrypoint: str,
    td: str,
    file_map: Dict[str, str],
    logger,
) -> List[Dict[str, str]]:
    pragma_details: List[Dict[str, str]] = []

    for rel in sorted(get_transitive_dependencies(entrypoint, td, file_map, logger)):
        content = find_content(rel, file_map, td, logger)
        if not content:
            continue

        match = PRAGMA_RE.search(content)
        if not match:
            continue

        pragma_details.append({"file": rel, "pragma": match.group(1).strip()})

    return pragma_details


def describe_dependency_source(rel_path: str, td: str) -> Dict[str, Optional[str]]:
    normalized = rel_path.replace("\\", "/")
    if not normalized.startswith("node_modules/"):
        return {"package": None, "package_version": None}

    segments = normalized.split("/")
    if len(segments) < 3:
        return {"package": None, "package_version": None}

    if segments[1].startswith("@") and len(segments) >= 4:
        package_name = f"{segments[1]}/{segments[2]}"
    else:
        package_name = segments[1]

    package_json_path = os.path.join(td, "node_modules", *package_name.split("/"), "package.json")
    package_version = None
    try:
        if os.path.exists(package_json_path):
            with open(package_json_path, "r", encoding="utf-8", errors="ignore") as handle:
                package_meta = json.load(handle)
                raw_version = package_meta.get("version")
                if isinstance(raw_version, str) and raw_version.strip():
                    package_version = raw_version.strip()
    except Exception:
        package_version = None

    return {"package": package_name, "package_version": package_version}


def explain_entrypoint_version_conflict(
    entrypoint: str,
    td: str,
    file_map: Dict[str, str],
    logger,
) -> Dict[str, object]:
    pragma_details = collect_entrypoint_pragmas(entrypoint, td, file_map, logger)
    enriched_details = []
    for item in pragma_details:
        source = describe_dependency_source(item["file"], td)
        enriched_details.append({**item, **source})

    unique_pragmas = sorted({item["pragma"] for item in enriched_details})
    return {
        "entrypoint": entrypoint,
        "files": enriched_details,
        "unique_pragmas": unique_pragmas,
        "hint": (
            "This usually means the imported libraries were fetched from a different version or commit than the target contract."
        ),
    }


def resolve_entrypoint_version(
    entrypoint: str,
    td: str,
    file_map: Dict[str, str],
    installed_versions: List[Version],
    get_local_solc_binary: Callable[[str], Optional[str]],
    logger,
) -> Optional[str]:
    pragma_details = collect_entrypoint_pragmas(entrypoint, td, file_map, logger)
    deps = {item["file"] for item in pragma_details}
    specs = []
    pragma_exprs: List[str] = []

    logger.info(f"Resolving version for {entrypoint}, found deps: {deps}")

    for item in pragma_details:
        rel = item["file"]
        expr = item["pragma"]
        pragma_exprs.append(expr)
        logger.info(f"Found pragma in {rel}: {expr}")
        try:
            specs.append(NpmSpec(expr))
        except ValueError:
            pass

    if not specs:
        logger.warning(f"No pragmas found for {entrypoint} closure. Strict mode failing.")
        return None

    candidate_versions = sorted(SUPPORTED_VERSIONS, reverse=True)

    preferred_candidate = None
    for version in candidate_versions:
        if all(spec.match(version) for spec in specs):
            preferred_candidate = version
            break

    for version in installed_versions:
        if all(spec.match(version) for spec in specs):
            if preferred_candidate and version != preferred_candidate:
                logger.warning(
                    f"Using installed fallback solc {version} for {entrypoint} (preferred {preferred_candidate} not locally available)"
                )
            else:
                logger.info(f"Selected installed version {version} for {entrypoint}")
            return str(version)

    if preferred_candidate:
        logger.info(
            f"Selected version {preferred_candidate} for {entrypoint} (will install if missing)"
        )
        return str(preferred_candidate)

    version_tokens: List[Tuple[int, int, int]] = []
    for expr in pragma_exprs:
        matches = re.findall(r"(\d+)\.(\d+)\.(\d+)", expr)
        for maj, minor, patch in matches:
            version_tokens.append((int(maj), int(minor), int(patch)))

    if version_tokens:
        dynamic_candidates: List[Version] = []
        seen_dynamic = set()

        for maj, minor, patch in sorted(version_tokens, reverse=True):
            key = f"{maj}.{minor}.{patch}"
            if key in seen_dynamic:
                continue
            seen_dynamic.add(key)
            dynamic_candidates.append(Version(key))

        families: Dict[Tuple[int, int], int] = {}
        for maj, minor, patch in version_tokens:
            family_key = (maj, minor)
            families[family_key] = max(families.get(family_key, 0), patch)

        for (maj, minor), max_patch in sorted(families.items(), reverse=True):
            for probe_patch in range(max_patch + 4, max_patch - 1, -1):
                if probe_patch < 0:
                    continue
                key = f"{maj}.{minor}.{probe_patch}"
                if key in seen_dynamic:
                    continue
                seen_dynamic.add(key)
                dynamic_candidates.append(Version(key))

        for candidate in dynamic_candidates:
            if all(spec.match(candidate) for spec in specs):
                local_candidate = get_local_solc_binary(str(candidate))
                if local_candidate:
                    logger.info(
                        f"Dynamically selected installed version {candidate} for {entrypoint}"
                    )
                    return str(candidate)

        for candidate in dynamic_candidates:
            if all(spec.match(candidate) for spec in specs):
                logger.info(
                    f"Dynamically selected version {candidate} for {entrypoint} (will install if missing)"
                )
                return str(candidate)

    logger.warning(f"No compatible version found for {specs}")
    return None
