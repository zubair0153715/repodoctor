"""RepoDoctor scanners. All checks are heuristics, never proof.

Secret-scan rule (hard): a report NEVER contains a matched secret value.
Only the file, line number, match type, and the line with the matched
span replaced by [REDACTED] are recorded.
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys

# ---------------------------------------------------------------- secrets

# Directories never scanned (dependency dirs, VCS metadata, build output).
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv",
    "venv", ".tox", "dist", "build", ".eggs",
}
# Binary / generated artefacts never scanned as text.
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar",
    ".gz", ".whl", ".so", ".dll", ".exe", ".bin", ".mp4", ".mp3",
    ".woff", ".woff2", ".ttf", ".eot", ".pyc", ".pyo",
}
MAX_FILE_BYTES = 1_000_000

# (display name, regex). Generic assignment patterns require a quoted value
# so ordinary words like "password" in prose do not match.
SECRET_PATTERNS = [
    ("Private key header",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("AWS access key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained token",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Slack token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Generic secret assignment",
     re.compile(
         r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd)"
         r"\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']")),
    ("Generic bearer token",
     re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-_.]{20,}\b")),
]

# Values that are obviously placeholders, not real secrets.
PLACEHOLDER_RE = re.compile(
    r"(?i)(example|your[_-]?|changeme|todo|xxx+|\*\*\*|placeholder|"
    r"insert[_-]?here|dummy)")


def _is_placeholder(matched: str) -> bool:
    return bool(PLACEHOLDER_RE.search(matched))


def _redact_line(line: str, start: int, end: int) -> str:
    return line[:start] + "[REDACTED]" + line[end:]


def iter_text_files(root: str):
    """Yield (absolute path, path relative to root) for scannable files."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            if os.path.splitext(name)[1].lower() in SKIP_EXTS:
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield full, os.path.relpath(full, root)


def scan_secrets(root: str) -> list[dict]:
    """Return [{file, line, type, redacted_line}] — never a secret value."""
    findings = []
    for full, rel in iter_text_files(root):
        try:
            with open(full, "rb") as fh:
                raw = fh.read()
            if b"\x00" in raw:  # binary file, skip
                continue
            text = raw.decode("utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    if _is_placeholder(match.group(0)):
                        continue
                    findings.append({
                        "file": rel,
                        "line": lineno,
                        "type": name,
                        "redacted_line": _redact_line(
                            line.strip(), match.start(), match.end()),
                    })
                    break  # one finding per line per pattern family is enough
    return findings


# ------------------------------------------------------------- dependencies

def _parse_requirement_line(line: str):
    line = line.strip()
    if not line or line.startswith(("#", "-", "!")):
        return None
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    match = re.match(r"([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)", line)
    if not match:
        return None
    name, spec = match.group(1), match.group(2).strip()
    version = ""
    vm = re.search(r"==\s*([^\s;,]+)", spec)
    if vm:
        version = vm.group(1)
    return {"name": name, "version": version, "spec": spec or "(unpinned)"}


def _parse_requirements(root: str, rel: str, deps: list):
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            for line in fh:
                parsed = _parse_requirement_line(line)
                if parsed:
                    parsed.update({"source": rel, "ecosystem": "PyPI"})
                    deps.append(parsed)
    except OSError:
        pass


def _parse_package_json(root: str, rel: str, deps: list, licenses: list):
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return
    for section in ("dependencies", "devDependencies",
                    "peerDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = spec.lstrip("^~>=< ") if isinstance(spec, str) else ""
            version = re.split(r"[\s,|]", version)[0]
            deps.append({"name": name, "version": version,
                         "spec": spec, "source": rel, "ecosystem": "npm"})
    lic = data.get("license")
    if isinstance(lic, str):
        licenses.append({"source": rel, "license": lic})
    elif isinstance(lic, dict) and lic.get("type"):
        licenses.append({"source": rel, "license": lic["type"]})


def _parse_go_mod(root: str, rel: str, deps: list):
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return
    for match in re.finditer(
            r"^\s*([A-Za-z0-9_.\-/]+)\s+v([0-9][^\s]*)", text, re.M):
        deps.append({"name": match.group(1), "version": match.group(2),
                     "spec": "v" + match.group(2), "source": rel,
                     "ecosystem": "Go"})


def _parse_pyproject(root: str, rel: str, deps: list, licenses: list):
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python < 3.11
        return
    try:
        with open(os.path.join(root, rel), "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError):
        return
    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        parsed = _parse_requirement_line(spec)
        if parsed:
            parsed.update({"source": rel, "ecosystem": "PyPI"})
            deps.append(parsed)
    lic = project.get("license")
    if isinstance(lic, dict) and lic.get("text"):
        licenses.append({"source": rel, "license": lic["text"]})
    elif isinstance(lic, str):
        licenses.append({"source": rel, "license": lic})


def _parse_cargo_toml(root: str, rel: str, deps: list, licenses: list):
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python < 3.11
        return
    try:
        with open(os.path.join(root, rel), "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError):
        return
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = ""
            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                version = str(spec.get("version", ""))
            deps.append({"name": name, "version": version, "spec": spec,
                         "source": rel, "ecosystem": "crates.io"})
    pkg = data.get("package") or {}
    if pkg.get("license"):
        licenses.append({"source": rel, "license": pkg["license"]})


MANIFESTS = {
    "requirements.txt": _parse_requirements,
    "requirements-dev.txt": _parse_requirements,
    "requirements/base.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "pyproject.toml": _parse_pyproject,
    "Cargo.toml": _parse_cargo_toml,
}


def scan_dependencies(root: str) -> tuple[list[dict], list[dict]]:
    """Return (deps, manifest_licenses). No vulnerability data here."""
    deps, licenses = [], []
    for rel, parser in MANIFESTS.items():
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            continue
        if parser in (_parse_package_json, _parse_pyproject, _parse_cargo_toml):
            parser(root, rel, deps, licenses)
        else:
            parser(root, rel, deps)
    # De-duplicate identical (ecosystem, name, version, source) rows.
    seen, unique = set(), []
    for dep in deps:
        key = (dep["ecosystem"], dep["name"], dep["version"], dep["source"])
        if key not in seen:
            seen.add(key)
            unique.append(dep)
    return unique, licenses


# ---------------------------------------------------------------- licenses

LICENSE_FILENAMES = {
    "LICENSE", "LICENCE", "COPYING", "LICENSE.md", "LICENSE.txt",
    "LICENCE.md", "LICENSE-MIT", "UNLICENSE", "COPYRIGHT",
}


def scan_licenses(root: str, manifest_licenses: list) -> dict:
    found = []
    try:
        top = sorted(os.listdir(root))
    except OSError:
        top = []
    for name in top:
        if name.upper() in LICENSE_FILENAMES:
            first_line = ""
            try:
                with open(os.path.join(root, name), encoding="utf-8",
                          errors="replace") as fh:
                    first_line = fh.readline().strip()[:120]
            except OSError:
                pass
            found.append({"file": name, "first_line": first_line})
    return {
        "repo_license_files": found,
        "manifest_licenses": manifest_licenses,
        "missing_repo_license": not found,
        "undeclared_manifest_license": not manifest_licenses,
    }


# --------------------------------------------------------------- dead code

def _module_names_for(rel_path: str) -> set[str]:
    """Candidate module names a Python file can be imported as."""
    stem = rel_path[:-3] if rel_path.endswith(".py") else rel_path
    parts = stem.replace(os.sep, ".").split(".")
    names = set()
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if parts:
        names.add(parts[-1])          # bare stem, e.g. `utils`
        names.add(".".join(parts))    # dotted path, e.g. `pkg.utils`
    return names


def scan_dead_code(root: str) -> list[dict]:
    """Python modules no other file imports. Candidates only — review first.

    Excludes __init__ files and files with a `__main__` guard (entry
    points), since those are legitimately never imported.
    """
    py_files = [rel for _, rel in iter_text_files(root)
                if rel.endswith(".py")]
    imported: set[str] = set()
    parsed: dict[str, str] = {}
    for rel in py_files:
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as fh:
                parsed[rel] = fh.read()
        except OSError:
            continue
    for rel, text in parsed.items():
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module)
    candidates = []
    for rel in py_files:
        if os.path.basename(rel) == "__init__.py":
            continue
        text = parsed.get(rel, "")
        if '__name__' in text and '__main__' in text:
            continue  # entry point: legitimately never imported
        names = _module_names_for(rel)
        if not (names & imported):
            candidates.append({
                "file": rel,
                "note": "No other file in this repo imports it. "
                        "Check entry points, plugins, dynamic imports "
                        "and scripts before deleting.",
            })
    return candidates


# ------------------------------------------------------------ OSV lookups

def lookup_vulnerabilities(deps: list, timeout: float = 15.0) -> dict:
    """Best-effort OSV (api.osv.dev, no key) lookup.

    Returns {"available": bool, "by_dep": {(ecosystem, name): [vuln,...]}}.
    On ANY failure the result is available=False and NO vulnerability is
    claimed — inventing CVEs is worse than saying "unknown".
    Each vuln entry is {"id": ..., "summary": ...} exactly as OSV reports.
    """
    import urllib.error
    import urllib.request

    queries = []
    index = []
    for dep in deps:
        if not dep["version"]:
            continue  # unpinned: OSV needs a version; skip, don't guess
        queries.append({"package": {"name": dep["name"],
                                    "ecosystem": dep["ecosystem"]},
                        "version": dep["version"]})
        index.append((dep["ecosystem"], dep["name"]))
    if not queries:
        return {"available": False, "by_dep": {}}
    payload = json.dumps({"queries": queries}).encode("utf-8")
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            data = json.load(resp)
    except Exception:
        return {"available": False, "by_dep": {}}
    by_dep: dict[tuple, list] = {}
    for key, result in zip(index, data.get("results", [])):
        vulns = [{"id": v.get("id", "?"),
                  "summary": (v.get("summary") or "")[:200]}
                 for v in result.get("vulns", [])]
        if vulns:
            by_dep[key] = vulns
    return {"available": True, "by_dep": by_dep}


def run_all(root: str, offline: bool = False) -> dict:
    """Run every check. Never writes into `root`."""
    secrets = scan_secrets(root)
    deps, manifest_licenses = scan_dependencies(root)
    licenses = scan_licenses(root, manifest_licenses)
    dead = scan_dead_code(root)
    vulns = {"available": False, "by_dep": {}} if offline \
        else lookup_vulnerabilities(deps)
    return {
        "secrets": secrets,
        "dependencies": deps,
        "vulnerabilities": vulns,
        "licenses": licenses,
        "dead_code": dead,
    }
