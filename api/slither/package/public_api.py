"""
Public-facing helper surface for the SentinelAudit Slither runner.

This module intentionally re-exports the reusable, method-heavy parts of the
runner without exposing the FastAPI server entrypoint, runtime secrets, or
deployment-specific wiring.
"""

from analyzer import (
    build_framework_findings_count,
    build_remappings,
    detect_framework_mode,
    explain_entrypoint_version_conflict,
    explain_framework_selection,
    extract_dependencies,
    install_dependencies,
    install_from_package_json,
    resolve_entrypoint_version,
    run_crytic_compile_preflight,
    run_slither_sync_with_framework,
    run_slither_sync_with_remappings,
    setup_import_paths,
    summarize_framework_compile_failure,
)

__all__ = [
    "build_framework_findings_count",
    "build_remappings",
    "detect_framework_mode",
    "explain_entrypoint_version_conflict",
    "explain_framework_selection",
    "extract_dependencies",
    "install_dependencies",
    "install_from_package_json",
    "resolve_entrypoint_version",
    "run_crytic_compile_preflight",
    "run_slither_sync_with_framework",
    "run_slither_sync_with_remappings",
    "setup_import_paths",
    "summarize_framework_compile_failure",
]
