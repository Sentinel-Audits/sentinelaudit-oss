import fnmatch
import json
import logging
import os
import re
import subprocess
from typing import Dict, List, Optional, Set, Tuple

from fastapi import HTTPException

logger = logging.getLogger(__name__)

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
TSCONFIG_MODULE_RE = re.compile(r'("module"\s*:\s*")([^"]+)(")', re.I)
TSCONFIG_MODULE_RESOLUTION_RE = re.compile(
    r'("moduleResolution"\s*:\s*")([^"]+)(")',
    re.I,
)
SUPPORTED_HARDHAT_TS_MODULES = {
    "none",
    "commonjs",
    "amd",
    "system",
    "umd",
    "es6",
    "es2015",
    "es2020",
    "es2022",
    "esnext",
    "node16",
    "nodenext",
}


def _workspace_has_any(cwd: str, candidates: List[str]) -> bool:
    return any(os.path.exists(os.path.join(cwd, candidate)) for candidate in candidates)


def detect_framework_mode(cwd: str, import_policy: Optional[dict] = None) -> Optional[str]:
    requested_framework = str((import_policy or {}).get("framework", "")).strip().lower()
    if requested_framework in {"foundry", "hardhat", "truffle", "brownie"}:
        return requested_framework

    has_foundry = os.path.exists(os.path.join(cwd, "foundry.toml"))
    has_remappings = os.path.exists(os.path.join(cwd, "remappings.txt"))
    has_lib_dir = os.path.isdir(os.path.join(cwd, "lib"))
    has_hardhat = _workspace_has_any(
        cwd,
        [
            "hardhat.config.ts",
            "hardhat.config.js",
            "hardhat.config.cjs",
            "hardhat.config.mjs",
        ],
    )
    has_truffle = _workspace_has_any(cwd, ["truffle-config.js", "truffle-config.ts"])
    has_brownie = _workspace_has_any(cwd, ["brownie-config.yaml", "brownie-config.yml"])

    if has_foundry and (has_lib_dir or has_remappings):
        return "foundry"
    if has_hardhat:
        return "hardhat"
    if has_truffle:
        return "truffle"
    if has_brownie:
        return "brownie"
    if has_foundry:
        return "foundry"
    return None


def explain_framework_selection(cwd: str, framework: Optional[str]) -> str:
    if not framework:
        return "no framework markers detected"
    if framework == "foundry":
        return "foundry.toml detected"
    if framework == "hardhat":
        return "hardhat.config.* detected"
    if framework == "truffle":
        return "truffle-config.* detected"
    if framework == "brownie":
        return "brownie-config.* detected"
    return f"{framework} requested"


def _raise_framework_error(
    status_code: int,
    error: str,
    message: str,
    details: str,
    suggestion: str,
):
    raise HTTPException(
        status_code=status_code,
        detail={
            "error": error,
            "message": message,
            "details": details[:2000] if details else "",
            "suggestion": suggestion,
        },
    )


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text or "")


def normalize_hardhat_tsconfig_modules(cwd: str) -> List[str]:
    patched_files: List[str] = []

    for root, dirs, files in os.walk(cwd):
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in {"node_modules", ".git", "artifacts", "cache", "dist", "build"}
        ]

        for name in files:
            if not fnmatch.fnmatch(name.lower(), "tsconfig*.json"):
                continue

            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    original = handle.read()
            except Exception:
                continue

            changed = False
            normalized_module = None

            def _replace(match: re.Match[str]) -> str:
                nonlocal changed, normalized_module
                current_value = match.group(2).strip()
                if current_value.lower() in SUPPORTED_HARDHAT_TS_MODULES:
                    return match.group(0)
                changed = True
                normalized_module = "commonjs"
                return f'{match.group(1)}commonjs{match.group(3)}'

            updated = TSCONFIG_MODULE_RE.sub(_replace, original)
            if normalized_module:

                def _replace_module_resolution(match: re.Match[str]) -> str:
                    nonlocal changed
                    current_value = match.group(2).strip().lower()
                    if current_value != "bundler":
                        return match.group(0)
                    changed = True
                    return f'{match.group(1)}node{match.group(3)}'

                updated = TSCONFIG_MODULE_RESOLUTION_RE.sub(
                    _replace_module_resolution,
                    updated,
                )

            if not changed or updated == original:
                continue

            with open(path, "w", encoding="utf-8") as handle:
                handle.write(updated)
            patched_files.append(path)

    if patched_files:
        logger.info(
            "Normalized unsupported tsconfig module values for Hardhat in: %s",
            ", ".join(os.path.relpath(path, cwd).replace("\\", "/") for path in patched_files),
        )

    return patched_files


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
            "Framework analysis completed without output",
            "",
            "The framework compile step completed without producing slither JSON output.",
        )

    with open(slither_json_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_framework_findings_count(raw: dict, entrypoints: List[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    detectors = []
    if isinstance(raw, dict):
        if isinstance(raw.get("results"), dict):
            detectors = raw["results"].get("detectors", []) or []
        elif isinstance(raw.get("detectors"), list):
            detectors = raw.get("detectors", []) or []

    normalized_entrypoints = {
        entry.replace("\\", "/"): entry
        for entry in entrypoints
        if isinstance(entry, str) and entry.endswith(".sol")
    }
    for entry in normalized_entrypoints.values():
        counts[entry] = 0

    for detector in detectors:
        seen_for_detector: Set[str] = set()
        for element in detector.get("elements", []) or []:
            source_mapping = element.get("source_mapping") or {}
            filename = (
                source_mapping.get("filename_relative")
                or source_mapping.get("filename_short")
                or ""
            )
            normalized_filename = str(filename).replace("\\", "/")
            if normalized_filename in normalized_entrypoints:
                seen_for_detector.add(normalized_entrypoints[normalized_filename])

        if not seen_for_detector:
            first_markdown = detector.get("first_markdown_element") or ""
            first_markdown = str(first_markdown).replace("\\", "/")
            for normalized_entrypoint, original_entrypoint in normalized_entrypoints.items():
                if normalized_entrypoint in first_markdown:
                    seen_for_detector.add(original_entrypoint)

        for entry in seen_for_detector:
            counts[entry] = counts.get(entry, 0) + 1

    return counts
