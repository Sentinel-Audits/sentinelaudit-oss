import os
import re
import json
import subprocess
import threading
import logging
from typing import Any, List, Optional, Dict, Set, Tuple
from fastapi import HTTPException
from semantic_version import NpmSpec, Version
from analyzer_dependency_versions import (
    detect_openzeppelin_version,
    extract_pragmas_from_files,
    infer_default_dependency_version,
)
from analyzer_framework import (
    build_framework_findings_count as framework_build_framework_findings_count,
    detect_framework_mode,
    explain_framework_selection,
    normalize_hardhat_tsconfig_modules,
    run_crytic_compile_preflight as framework_run_crytic_compile_preflight,
    run_slither_sync_with_framework as framework_run_slither_sync_with_framework,
    strip_ansi as framework_strip_ansi,
    summarize_framework_compile_failure as framework_summarize_framework_compile_failure,
)
from analyzer_entrypoints import (
    collect_entrypoint_pragmas as entrypoint_collect_entrypoint_pragmas,
    describe_dependency_source as entrypoint_describe_dependency_source,
    explain_entrypoint_version_conflict as entrypoint_explain_entrypoint_version_conflict,
    find_content as entrypoint_find_content,
    get_transitive_dependencies as entrypoint_get_transitive_dependencies,
    resolve_entrypoint_version as entrypoint_resolve_entrypoint_version,
    resolve_import_to_disk as entrypoint_resolve_import_to_disk,
)
from analyzer_packages import (
    build_remappings as package_build_remappings,
    extract_dependencies as package_extract_dependencies,
    infer_imported_packages as package_infer_imported_packages,
    install_dependencies as package_install_dependencies,
    install_from_package_json as package_install_from_package_json,
    parse_workspace_remappings_from_files as package_parse_workspace_remappings_from_files,
    setup_import_paths as package_setup_import_paths,
)
from schemas import FileIn, RunReq

logger = logging.getLogger(__name__)

# Global lock to prevent race conditions when switching compiler versions
SOLC_LOCK = threading.Lock()

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
IMPORT_RE = re.compile(r'import\s+(?:[^"\']*\s+from\s+)?["\']([^"\']+)["\']')
REMAPPING_ENTRY_RE = re.compile(r'["\']([^"\']+?)=([^"\']+)["\']')
ALIAS_TOKEN_RE = re.compile(r"[a-z0-9]+", re.I)


def parse_workspace_remappings_from_files(files: List[FileIn]) -> Dict[str, str]:
    remappings: Dict[str, str] = {}

    for file in files:
        normalized_path = (file.path or "").replace("\\", "/")
        base_name = normalized_path.split("/")[-1]

        if base_name == "remappings.txt":
            for line in (file.content or "").splitlines():
                entry = line.strip()
                if not entry or entry.startswith("#") or "=" not in entry:
                    continue
                prefix, target = entry.split("=", 1)
                remappings[prefix.strip()] = target.strip()
            continue

        if base_name == "foundry.toml":
            content = file.content or ""
            for block in re.findall(r"remappings\s*=\s*\[(.*?)\]", content, flags=re.S):
                for prefix, target in REMAPPING_ENTRY_RE.findall(block):
                    remappings[prefix.strip()] = target.strip()

    return remappings


def _is_solidity_file(path: Optional[str]) -> bool:
    normalized = (path or "").replace("\\", "/").lower()
    return normalized.endswith(".sol")


def _is_node_modules_target(target: str) -> bool:
    normalized = (target or "").replace("\\", "/").lower()
    return "node_modules/" in normalized or normalized.startswith("node_modules/")


def _alias_tokens(value: str) -> Set[str]:
    tokens = {
        token.lower()
        for token in ALIAS_TOKEN_RE.findall(value.replace("@", " "))
        if token
    }
    return {
        token
        for token in tokens
        if token not in {"contracts", "contract", "lib", "src", "node", "modules"}
        and not re.fullmatch(r"v\d+", token)
        and not re.fullmatch(r"\d+", token)
    }


def _alias_prefers_upgradeable(alias_prefix: str, import_path: str) -> bool:
    lowered = f"{alias_prefix} {import_path}".lower()
    return "upgradeable" in lowered


def _match_alias_prefix_for_import(
    import_path: str,
    remappings: Dict[str, str],
) -> Optional[str]:
    normalized_import = import_path.replace("\\", "/").lstrip("./").lstrip("/")
    canonical_import = normalized_import.lstrip("@")

    matches: List[Tuple[int, str]] = []
    for prefix, target in remappings.items():
        if not prefix or _is_node_modules_target(target):
            continue

        normalized_prefix = prefix.replace("\\", "/").strip().rstrip("/")
        if not normalized_prefix:
            continue

        candidates = {normalized_prefix, normalized_prefix.lstrip("@")}
        if not normalized_prefix.startswith("@"):
            candidates.add(f"@{normalized_prefix}")

        for candidate in candidates:
            candidate_import = candidate.lstrip("@")
            if (
                canonical_import == candidate_import
                or canonical_import.startswith(f"{candidate_import}/")
            ):
                matches.append((len(candidate_import), normalized_prefix))
                break

    if not matches:
        return None

    matches.sort(reverse=True)
    return matches[0][1]


def _should_force_inferred_version(alias_prefix: str, resolved_package: str) -> bool:
    lowered_alias = alias_prefix.lower()
    if "openzeppelin" in lowered_alias and re.search(r"v\d+", lowered_alias):
        return resolved_package in {
            "@openzeppelin/contracts",
            "@openzeppelin/contracts-upgradeable",
        }
    return False


def _resolve_manifest_alias_package(
    alias_prefix: str,
    import_path: str,
    declared_dependencies: Dict[str, str],
) -> Optional[str]:
    if not declared_dependencies:
        return None

    alias_tokens = _alias_tokens(alias_prefix)
    if not alias_tokens:
        return None

    prefers_upgradeable = _alias_prefers_upgradeable(alias_prefix, import_path)
    best_package: Optional[str] = None
    best_score = float("-inf")

    for package_name in declared_dependencies.keys():
        package_tokens = _alias_tokens(package_name)
        if not package_tokens:
            continue

        overlap = alias_tokens & package_tokens
        if not overlap:
            continue

        score = len(overlap) * 4
        package_lower = package_name.lower()
        if prefers_upgradeable:
            score += 5 if "upgradeable" in package_lower else -4
        elif "upgradeable" in package_lower:
            score -= 1

        if package_lower.endswith("/contracts"):
            score += 2
        if package_lower.endswith("/contracts-upgradeable"):
            score += 2

        if score > best_score:
            best_score = score
            best_package = package_name

    return best_package if best_score > 0 else None


def summarize_framework_compile_failure(
    details: str,
    framework: str,
) -> Tuple[str, str]:
    cleaned = strip_ansi(details).replace("\r", "").strip()
    compact = re.sub(r"\n(?:stdout|stderr):\s*", "\n", cleaned)
    compact = re.sub(r"\n{3,}", "\n\n", compact)

    if "Encountered invalid solc version" in compact and "openzeppelin" in compact.lower():
        requested_versions = ", ".join(
            sorted(set(re.findall(r"\^0\.8\.\d+", compact)))
        )
        summary = (
            "Installed OpenZeppelin dependencies are newer than the compiler version this repo targets."
        )
        if requested_versions:
            summary += f" Resolved library files require {requested_versions}."
        summary += (
            " Use the repo's pinned dependencies or pin both @openzeppelin/contracts and "
            "@openzeppelin/contracts-upgradeable to a compatible release such as 4.8.0 for Solidity 0.8.0-0.8.7, 4.9.6 for Solidity 0.8.8-0.8.19, or 5.0.2 for Solidity 0.8.20."
        )
        return (
            summary,
            "Pin the dependency versions to the repo's intended OpenZeppelin release, or upload the original lib/ vendor directories instead of relying on latest npm packages.",
        )

    missing_lib_match = re.search(r'\"([^\"]*?/lib/[^\"]+)\": No such file or directory', compact)
    if missing_lib_match:
        missing_path = missing_lib_match.group(1)
        return (
            f"Foundry could not resolve a vendored dependency path: {missing_path}",
            "Upload the repo's lib/ dependencies or include the framework files and remappings that map that import prefix correctly.",
        )

    invalid_module_match = re.search(
        r"TS6046: Argument for '--module' option.*?(?:\n|^).*?(?:\"module\"\s*[:=]\s*\"([^\"]+)\"|module[^\n]*?([a-zA-Z0-9_-]+))?",
        compact,
        flags=re.I | re.S,
    )
    if framework == "hardhat" and "TS6046" in compact and "--module" in compact:
        invalid_module = (
            (invalid_module_match.group(1) if invalid_module_match else None)
            or (invalid_module_match.group(2) if invalid_module_match else None)
            or "an unsupported value"
        )
        return (
            f"Hardhat failed before Solidity compilation because the workspace TypeScript config uses an unsupported compilerOptions.module value ({invalid_module}).",
            "Pin compilerOptions.module in tsconfig*.json to a Hardhat-compatible value such as commonjs or nodenext, or let Sentinel normalize the temp workspace before compile.",
        )

    tail = compact[:900].strip()
    if len(compact) > 900:
        tail += "\n…"
    return (
        tail,
        f"Ensure the {framework} project compiles locally and all dependencies and vendored libraries are present in the uploaded workspace.",
    )


def run_crytic_compile_preflight(cwd: str, framework: str) -> None:
    if framework == "hardhat":
        normalize_hardhat_tsconfig_modules(cwd)
    cmd = ["crytic-compile", ".", "--compile-force-framework", framework]
    logger.info(f"Running crytic-compile preflight: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        _raise_framework_error(
            504,
            "CRYTIC_COMPILE_TIMEOUT",
            f"{framework} compilation timed out",
            "",
            "The project compile step exceeded the 10 minute limit.",
        )

    if result.returncode != 0:
        details = result.stderr or result.stdout or ""
        summary, suggestion = summarize_framework_compile_failure(details, framework)
        logger.error(
            "crytic-compile preflight failed for %s\nsummary: %s\nraw: %s",
            framework,
            summary,
            strip_ansi(details)[:4000],
        )
        _raise_framework_error(
            400,
            "CRYTIC_COMPILE_FAILED",
            f"{framework} compilation failed",
            summary,
            suggestion,
        )


def run_slither_sync_with_framework(cwd: str, framework: str) -> dict:
    if framework == "hardhat":
        normalize_hardhat_tsconfig_modules(cwd)
    output_file = "slither.framework.raw.json"
    slither_json_path = os.path.join(cwd, output_file)
    cmd = [
        "slither",
        ".",
        "--json",
        output_file,
        "--compile-force-framework",
        framework,
    ]
    logger.info(f"Slither framework command: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        _raise_framework_error(
            504,
            "SLITHER_TIMEOUT",
            f"Slither {framework} analysis timed out",
            "",
            "The project may be too large or the framework compile step is hanging.",
        )

    if result.returncode != 0 and not os.path.exists(slither_json_path):
        err = result.stderr or result.stdout or ""
        summary, suggestion = summarize_framework_compile_failure(err, framework)
        logger.error(
            "slither framework analysis failed for %s\nsummary: %s\nraw: %s",
            framework,
            summary,
            strip_ansi(err)[:4000],
        )
        _raise_framework_error(
            500,
            "SLITHER_ANALYSIS_FAILED",
            f"Slither {framework} analysis failed",
            summary,
            suggestion,
        )

    if not os.path.exists(slither_json_path):
        _raise_framework_error(
            500,
            "SLITHER_OUTPUT_MISSING",
            "Slither completed but no results file was generated",
            "",
            "Please retry the analysis.",
        )

    try:
        with open(slither_json_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        _raise_framework_error(
            500,
            "SLITHER_OUTPUT_PARSE_ERROR",
            "Failed to parse framework analysis results",
            str(exc),
            "Please retry the analysis.",
        )


def build_framework_findings_count(raw: dict, entrypoints: List[str]) -> Dict[str, int]:
    detectors = []
    if "results" in raw and isinstance(raw["results"], dict):
        detectors = raw["results"].get("detectors", [])
    elif "detectors" in raw and isinstance(raw["detectors"], list):
        detectors = raw["detectors"]

    counts: Dict[str, int] = {ep: 0 for ep in entrypoints if ep.endswith(".sol")}
    normalized_entrypoints = {
        ep: ep.replace("\\", "/").lstrip("./")
        for ep in counts.keys()
    }

    for detector in detectors:
        seen_for_detector: Set[str] = set()
        for element in detector.get("elements", []):
            filename = (
                element.get("source_mapping", {}).get("filename_relative", "") or ""
            ).replace("\\", "/").lstrip("./")
            if not filename:
                continue
            for original, normalized in normalized_entrypoints.items():
                if (
                    filename == normalized
                    or filename.endswith(f"/{normalized}")
                    or normalized.endswith(f"/{filename}")
                ):
                    seen_for_detector.add(original)
        for matched in seen_for_detector:
            counts[matched] += 1

    return counts


# Keep analyzer.py as the compatibility import surface while delegating the
# live framework implementation to the smaller helper module.
strip_ansi = framework_strip_ansi
summarize_framework_compile_failure = framework_summarize_framework_compile_failure
run_crytic_compile_preflight = framework_run_crytic_compile_preflight
run_slither_sync_with_framework = framework_run_slither_sync_with_framework
build_framework_findings_count = framework_build_framework_findings_count

def get_solc_artifacts_dir() -> str:
    solc_home = os.environ.get("SOLC_CACHE", "/home/runner/.solc-select")
    return os.path.join(solc_home, "artifacts")

def get_local_solc_binary(version: str) -> Optional[str]:
    artifacts_dir = get_solc_artifacts_dir()
    if not os.path.isdir(artifacts_dir):
        return None

    # Common solc-select layouts:
    # - artifacts/solc-0.8.30
    # - artifacts/solc-0.8.30/solc
    # - artifacts/solc-0.8.30/solc-0.8.30
    # - artifacts/solc-0.8.30/bin/solc
    candidate_dirs = [
        os.path.join(artifacts_dir, f"solc-{version}"),
    ]
    # Some installations include commit/build suffixes in directory names.
    try:
        for entry in os.listdir(artifacts_dir):
            if entry.startswith(f"solc-{version}") and entry not in {f"solc-{version}"}:
                candidate_dirs.append(os.path.join(artifacts_dir, entry))
    except Exception:
        pass

    candidate_files = [
        os.path.join(artifacts_dir, f"solc-{version}"),
        os.path.join(artifacts_dir, f"solc-{version}", "solc"),
        os.path.join(artifacts_dir, f"solc-{version}", f"solc-{version}"),
        os.path.join(artifacts_dir, f"solc-{version}", "bin", "solc"),
    ]
    for directory in candidate_dirs:
        candidate_files.extend(
            [
                os.path.join(directory, "solc"),
                os.path.join(directory, f"solc-{version}"),
                os.path.join(directory, "bin", "solc"),
            ]
        )

    seen = set()
    for candidate in candidate_files:
        if candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate):
            return candidate

    # Final fallback: scan matching artifact directories for any executable-like solc file.
    for directory in candidate_dirs:
        if not os.path.isdir(directory):
            continue
        try:
            for root, _, files in os.walk(directory):
                for file_name in files:
                    if not file_name.startswith("solc"):
                        continue
                    candidate = os.path.join(root, file_name)
                    if os.path.isfile(candidate):
                        return candidate
        except Exception:
            continue
    return None

def get_installed_solc_versions() -> List[Version]:
    artifacts_dir = get_solc_artifacts_dir()
    if not os.path.isdir(artifacts_dir):
        return []

    versions: List[Version] = []
    seen = set()

    try:
        for entry in os.listdir(artifacts_dir):
            if not entry.startswith("solc-"):
                continue
            version_str = entry[len("solc-") :]
            if version_str in seen:
                continue
            binary = get_local_solc_binary(version_str)
            if not binary:
                continue
            try:
                versions.append(Version(version_str))
                seen.add(version_str)
            except ValueError:
                continue
    except Exception:
        return []

    return sorted(versions, reverse=True)

def ensure_solc_binary(version: str) -> str:
    """
    Ensure a compiler binary exists locally and return its path.
    Avoids `solc-select use`, which can trigger remote metadata checks.
    """
    existing = get_local_solc_binary(version)
    if existing:
        return existing

    logger.info(f"Local solc {version} not found. Attempting installation...")
    try:
        p = subprocess.run(
            ["solc-select", "install", version],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "SOLC_INSTALL_TIMEOUT",
                "message": f"Timed out installing solc {version}.",
                "suggestion": "Retry later or pre-install the compiler in the runner image.",
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "SOLC_INSTALL_FAILED",
                "message": f"Failed to install solc {version}.",
                "details": str(e),
                "suggestion": "Ensure runner has network access to Solidity compiler mirrors or pre-install versions.",
            },
        )

    if p.returncode != 0:
        install_output = (p.stderr or p.stdout or "")[:2000]
        if "HTTP Error 403" in install_output or "Forbidden" in install_output:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "SOLC_VERSION_UNAVAILABLE",
                    "code": "SOLC_VERSION_UNAVAILABLE",
                    "message": f"Compiler version {version} is unavailable in this runtime environment.",
                    "details": install_output[:1000],
                    "suggestion": "This runner cannot download solc at runtime. Use a pre-baked compiler image/cache or retry with a nearby supported pragma.",
                },
            )
        raise HTTPException(
            status_code=503,
            detail={
                "error": "SOLC_INSTALL_FAILED",
                "code": "SOLC_INSTALL_FAILED",
                "message": f"Failed to install solc {version}.",
                "details": install_output[:1000],
                "suggestion": "Ensure runner can access compiler metadata/download hosts, or pre-install this version.",
            },
        )

    installed = get_local_solc_binary(version)
    if installed:
        return installed

    raise HTTPException(
        status_code=503,
        detail={
            "error": "SOLC_NOT_FOUND_AFTER_INSTALL",
            "message": f"solc {version} was reported installed but binary was not found.",
            "suggestion": "Verify SOLC_CACHE path and image provisioning of solc-select artifacts.",
        },
    )

# Delegate entrypoint/dependency-graph behavior to the extracted module while
# keeping analyzer.py as the compatibility import surface.
find_content = lambda path, file_map, td: entrypoint_find_content(path, file_map, td, logger)
resolve_import_to_disk = entrypoint_resolve_import_to_disk
get_transitive_dependencies = (
    lambda entrypoint_path, td, file_map: entrypoint_get_transitive_dependencies(
        entrypoint_path,
        td,
        file_map,
        logger,
    )
)
collect_entrypoint_pragmas = (
    lambda entrypoint, td, file_map: entrypoint_collect_entrypoint_pragmas(
        entrypoint,
        td,
        file_map,
        logger,
    )
)
describe_dependency_source = entrypoint_describe_dependency_source
explain_entrypoint_version_conflict = (
    lambda entrypoint, td, file_map: entrypoint_explain_entrypoint_version_conflict(
        entrypoint,
        td,
        file_map,
        logger,
    )
)
resolve_entrypoint_version = (
    lambda entrypoint, td, file_map: entrypoint_resolve_entrypoint_version(
        entrypoint,
        td,
        file_map,
        get_installed_solc_versions(),
        get_local_solc_binary,
        logger,
    )
)

parse_workspace_remappings_from_files = package_parse_workspace_remappings_from_files
infer_imported_packages = package_infer_imported_packages
extract_dependencies = lambda files, preferred_package_json_path=None: package_extract_dependencies(
    files,
    preferred_package_json_path,
    logger,
)
install_dependencies = lambda packages, cwd: package_install_dependencies(packages, cwd, logger)
install_from_package_json = (
    lambda cwd, include_dev_dependencies=False: package_install_from_package_json(
        cwd,
        include_dev_dependencies,
        logger,
    )
)
build_remappings = package_build_remappings
setup_import_paths = package_setup_import_paths

def run_slither_sync_with_remappings(
    req: RunReq,
    solc: str,
    cwd: str,
    ep: str,
    remappings: str = "",
    solc_binary: Optional[str] = None,
) -> dict:
    """Run Slither analysis synchronously with remappings"""
    
    # Find file object that matches this entrypoint
    entrypoint_file = None
    for f in req.files:
        if f.path.endswith(ep):
            entrypoint_file = f
            break
    
    if not entrypoint_file:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "ENTRYPOINT_NOT_FOUND",
                "message": f"Entrypoint file '{ep}' not found in uploaded files",
                "suggestion": "Make sure all entrypoint files are included in upload"
            }
        )
    
    ep_path = os.path.join(cwd, entrypoint_file.path)
    if not os.path.exists(ep_path):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "ENTRYPOINT_FILE_MISSING",
                "message": f"Entrypoint file not found on disk: {ep}",
                "suggestion": "Please try uploading the files again"
            }
        )

    # Unique output filename per entrypoint
    ep_basename = os.path.basename(ep)
    output_file = f"slither.{ep_basename}.raw.json"
    slither_json_path = os.path.join(cwd, output_file)

    # Build solc args first
    node_modules_path = os.path.join(cwd, "node_modules")
    
    try:
        solc_v = Version(solc)
    except ValueError:
        # Fallback if version string is weird
        solc_v = Version("0.8.0") 

    cmd = [
        "slither",
        ep_path,
        "--json", output_file,
    ]

    if solc_binary:
        cmd.extend(["--solc", solc_binary])
    
    # Add remappings directly to slither command (not through solc-args)
    if remappings:
        # Use --solc-remaps for all versions (Slither will handle version differences)
        cmd.extend(["--solc-remaps", remappings])

    # Allow solc to read local workspace + node_modules paths.
    # This avoids "import not found" issues in containerized runs.
    allow_paths = [cwd, os.path.join(cwd, "node_modules")]
    cmd.extend(["--solc-args", f"--allow-paths {','.join(allow_paths)}"])
    
    logger.info(f"Slither command for {ep} (ver {solc}): {' '.join(cmd[3:])}")
    
    try:
        # Added timeout=600 (10 minutes)
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600)
        code, out, err = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Slither timed out for {ep}")
        raise HTTPException(
            status_code=504,
            detail={
                "error": "SLITHER_TIMEOUT",
                "message": "Analysis timed out (exceeded 10 minutes)",
                "suggestion": "The contract might be too complex or large."
            }
        )
            
    if code != 0:
        # Slither returns exit code = number of findings. This is NOT an error if JSON is produced.
        # Only treat as error if output file is missing.
        if not os.path.exists(slither_json_path):
            def tail(value: str, limit: int = 4000) -> str:
                if not value:
                    return ""
                return value[-limit:]

            # Parse common compilation errors
            error_detail = {
                "error": "SLITHER_ANALYSIS_FAILED",
                "message": "Static analysis failed",
                "details": tail(err) if err else "Unknown error during analysis",
                "stdout": tail(out) if out else "",
                "entrypoint": ep
            }
            
            if "Source file requires different compiler version" in err:
                error_detail.update({
                    "error": "COMPILER_VERSION_MISMATCH",
                    "message": "Compiler version mismatch between files",
                    "suggestion": "Ensure all files use compatible Solidity versions"
                })
            elif "Import not found" in err or "File not found" in err:
                error_detail.update({
                    "error": "IMPORT_ERROR",
                    "message": "Missing import or dependency",
                    "suggestion": "Check that all imported files are included in upload"
                })
            elif "SyntaxError" in err:
                error_detail.update({
                    "error": "SYNTAX_ERROR",
                    "message": "Solidity syntax error in your code",
                    "suggestion": "Review your code for syntax issues"
                })
            
            raise HTTPException(status_code=500, detail=error_detail)

    if not os.path.exists(slither_json_path):
        raise HTTPException(
            status_code=500,
            detail={
                "error": "SLITHER_OUTPUT_MISSING",
                "message": "Analysis completed but no results file was generated",
                "suggestion": "This may indicate an issue with the analysis process. Please try again."
            }
        )
    
    try:
        with open(slither_json_path, "r", encoding="utf-8") as r:
            raw = json.load(r)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "SLITHER_OUTPUT_PARSE_ERROR",
                "message": "Failed to parse analysis results",
                "details": str(e),
                "suggestion": "The analysis output was corrupted. Please try running the analysis again."
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "SLITHER_OUTPUT_READ_ERROR",
                "message": "Error reading analysis results",
                "details": str(e),
                "suggestion": "Please try running the analysis again."
            }
        )
        
    return raw
