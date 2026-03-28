import json
import os
import re
import subprocess
from typing import Dict, List, Optional, Set, Tuple

from schemas import FileIn
from analyzer_dependency_versions import infer_default_dependency_version

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


def infer_imported_packages(files: List[FileIn]) -> Dict[str, bool]:
    packages: Dict[str, bool] = {}
    pkg_re = re.compile(r"^(@[a-z0-9-_]+/[a-z0-9-_.]+|[a-z0-9-_.]+)$", re.I)
    remappings = parse_workspace_remappings_from_files(files)
    declared_dependencies: Dict[str, str] = {}

    for file in files:
        if (file.path.split("/")[-1] if file.path else "") != "package.json":
            continue
        try:
            package_data = json.loads(file.content or "{}")
        except Exception:
            continue
        declared_dependencies.update(package_data.get("dependencies", {}) or {})
        declared_dependencies.update(package_data.get("devDependencies", {}) or {})

    def normalize_vendor_package(candidate: str) -> tuple[str, bool]:
        lowered = candidate.lower()
        if lowered == "openzeppelin-contracts":
            return "@openzeppelin/contracts", False
        if lowered == "openzeppelin-contracts-upgradeable":
            return "@openzeppelin/contracts-upgradeable", False
        return candidate, False

    for file in files:
        if not _is_solidity_file(file.path):
            continue
        imports = IMPORT_RE.findall(file.content or "")
        for imp in imports:
            if imp.startswith("./") or imp.startswith("../"):
                continue
            if "/" not in imp and imp.lower().endswith(".sol"):
                continue

            pkg_name: Optional[str] = None
            force_inferred_version = False
            matched_alias_prefix = _match_alias_prefix_for_import(imp, remappings)
            if imp.startswith("@"):
                parts = imp.split("/")
                if len(parts) >= 2:
                    candidate = f"{parts[0]}/{parts[1]}"
                    if pkg_re.match(candidate):
                        if matched_alias_prefix:
                            resolved = _resolve_manifest_alias_package(
                                matched_alias_prefix,
                                imp,
                                declared_dependencies,
                            )
                            if resolved:
                                pkg_name = resolved
                                force_inferred_version = _should_force_inferred_version(
                                    matched_alias_prefix,
                                    resolved,
                                )
                        else:
                            pkg_name, force_inferred_version = normalize_vendor_package(
                                candidate
                            )
            else:
                candidate = imp.split("/")[0]
                if candidate and pkg_re.match(candidate):
                    if matched_alias_prefix:
                        resolved = _resolve_manifest_alias_package(
                            matched_alias_prefix,
                            imp,
                            declared_dependencies,
                        )
                        if resolved:
                            pkg_name = resolved
                            force_inferred_version = _should_force_inferred_version(
                                matched_alias_prefix,
                                resolved,
                            )
                    else:
                        pkg_name, force_inferred_version = normalize_vendor_package(
                            candidate
                        )

            if pkg_name:
                packages[pkg_name] = packages.get(pkg_name, False) or force_inferred_version

    return packages


def extract_dependencies(
    files: List[FileIn],
    preferred_package_json_path: Optional[str] = None,
    logger=None,
) -> Dict[str, str]:
    packages: Dict[str, str] = {}

    package_files: Dict[str, str] = {}
    for file in files:
        if (file.path.split("/")[-1] if file.path else "") == "package.json":
            package_files[file.path] = file.content

    selected_package_path: Optional[str] = None
    if package_files:
        if preferred_package_json_path and preferred_package_json_path in package_files:
            selected_package_path = preferred_package_json_path
        elif "package.json" in package_files:
            selected_package_path = "package.json"
        elif len(package_files) == 1:
            selected_package_path = next(iter(package_files.keys()))
        else:
            selected_package_path = min(
                package_files.keys(),
                key=lambda path: (path.count("/"), path),
            )

    if selected_package_path:
        try:
            package_data = json.loads(package_files[selected_package_path])
            deps = {
                **package_data.get("dependencies", {}),
                **package_data.get("devDependencies", {}),
            }
            imported_packages = infer_imported_packages(files)

            if imported_packages:
                selected: Dict[str, str] = {}
                for pkg_name in sorted(imported_packages):
                    if pkg_name in {
                        "@openzeppelin/contracts",
                        "@openzeppelin/contracts-upgradeable",
                    }:
                        selected[pkg_name] = infer_default_dependency_version(pkg_name, files)
                    elif pkg_name in deps and not imported_packages[pkg_name]:
                        selected[pkg_name] = deps[pkg_name]
                    else:
                        selected[pkg_name] = infer_default_dependency_version(pkg_name, files)

                if logger:
                    logger.info(
                        f"Using Solidity-imported dependencies from {selected_package_path}: {selected}"
                    )
                return selected

            if logger:
                logger.info(
                    f"{selected_package_path} found, but no external Solidity imports detected; "
                    f"falling back to direct import scan."
                )
        except json.JSONDecodeError as exc:
            if logger:
                logger.warning(f"Failed to parse {selected_package_path}: {exc}")
        except Exception as exc:
            if logger:
                logger.warning(f"Error reading {selected_package_path}: {exc}")

    pkg_re = re.compile(r"^(@[a-z0-9-_]+/[a-z0-9-_.]+|[a-z0-9-_.]+)$", re.I)

    for file in files:
        if not _is_solidity_file(file.path):
            continue
        imports = IMPORT_RE.findall(file.content or "")
        for imp in imports:
            if imp.startswith("./") or imp.startswith("../"):
                continue

            pkg_name = None
            if imp.startswith("@"):
                parts = imp.split("/")
                if len(parts) >= 2:
                    candidate = f"{parts[0]}/{parts[1]}"
                    if pkg_re.match(candidate):
                        pkg_name = candidate
            else:
                candidate = imp.split("/")[0]
                if candidate and pkg_re.match(candidate):
                    lowered = candidate.lower()
                    if lowered == "openzeppelin-contracts":
                        pkg_name = "@openzeppelin/contracts"
                    elif lowered == "openzeppelin-contracts-upgradeable":
                        pkg_name = "@openzeppelin/contracts-upgradeable"
                    else:
                        pkg_name = candidate

            if pkg_name:
                version = infer_default_dependency_version(pkg_name, files)
                if version != "latest":
                    packages[pkg_name] = version
                elif pkg_name not in packages:
                    packages[pkg_name] = "latest"

    return packages


def install_dependencies(packages: Dict[str, str], cwd: str, logger=None) -> bool:
    if not packages:
        return True

    install_args = []
    for pkg, ver in packages.items():
        if ver and ver != "latest":
            install_args.append(f"{pkg}@{ver}")
        else:
            install_args.append(pkg)

    if logger:
        logger.info(f"Installing packages with Bun: {install_args}")

    # Avoid bun init timeout by writing a minimal package.json ourselves if missing.
    pkg_json = os.path.join(cwd, "package.json")
    if not os.path.exists(pkg_json):
        try:
            with open(pkg_json, "w", encoding="utf-8") as f:
                f.write('{"name":"slither-workspace","private":true}')
        except Exception as exc:
            if logger:
                logger.error(f"Failed to create package.json: {exc}")
            return False

    cmd = ["bun", "add", "--no-save", "--no-cache", "--ignore-scripts"] + install_args
    try:
        process = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900)
        if process.returncode != 0:
            if logger:
                logger.error(f"bun install failed: {process.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        if logger:
            logger.error("bun install timed out")
        return False


def install_from_package_json(
    cwd: str,
    include_dev_dependencies: bool = False,
    logger=None,
) -> bool:
    if logger:
        logger.info(
            "Installing dependencies from package.json with Bun%s",
            " (including devDependencies)" if include_dev_dependencies else "",
        )

    try:
        cmd = ["bun", "install", "--ignore-scripts"]
        if not include_dev_dependencies:
            cmd.append("--production")
        process = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900)
        if process.returncode != 0:
            if logger:
                logger.error(f"bun install failed: {process.stderr}")
            return False
        if logger:
            logger.info("Successfully installed from package.json")
        return True
    except subprocess.TimeoutExpired:
        if logger:
            logger.error("bun install timed out")
        return False


def build_remappings(td: str, packages: List[str]) -> str:
    nm = os.path.join(td, "node_modules")
    remaps = []

    for pkg_spec in packages:
        if pkg_spec.startswith("@"):
            last_at = pkg_spec.rfind("@")
            pkg = pkg_spec[:last_at] if last_at > 0 else pkg_spec
        else:
            pkg = pkg_spec.split("@", 1)[0]

        if pkg.startswith("@"):
            parts = pkg.split("/")
            if len(parts) >= 2:
                ns, name = parts[0], parts[1]
                full_path = os.path.join(nm, ns, name).replace("\\", "/")
                remaps.append(f"{ns}/{name}={full_path}")
            else:
                path = os.path.join(nm, pkg).replace("\\", "/")
                remaps.append(f"{pkg}={path}")
        else:
            path = os.path.join(nm, pkg).replace("\\", "/")
            remaps.append(f"{pkg}={path}")

    forge_std_src_abs = os.path.join(nm, "forge-std", "src").replace("\\", "/")
    forge_std_root_abs = os.path.join(nm, "forge-std").replace("\\", "/")

    if os.path.exists(os.path.join(nm, "forge-std", "src")):
        remaps.append(f"forge-std={forge_std_src_abs}")
    elif os.path.exists(os.path.join(nm, "forge-std")):
        remaps.append(f"forge-std={forge_std_root_abs}")

    seen = set()
    out = []
    for remap in remaps:
        if remap not in seen:
            seen.add(remap)
            out.append(remap)

    return " ".join(out)


def setup_import_paths(dependencies: List[str], cwd: str) -> None:
    if not dependencies:
        return

    node_modules_path = os.path.join(cwd, "node_modules")
    if not os.path.exists(node_modules_path):
        return

    for package in dependencies:
        if package.startswith("@"):
            parts = package.split("/")
            namespace = parts[0]
            namespace_dir = os.path.join(cwd, namespace)
            namespace_node_modules = os.path.join(node_modules_path, namespace)

            if os.path.exists(namespace_node_modules) and not os.path.exists(namespace_dir):
                try:
                    os.symlink(namespace_node_modules, namespace_dir)
                except Exception:
                    pass
