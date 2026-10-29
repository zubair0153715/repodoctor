"""Build the single self-contained HTML report (inline CSS, no assets)."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from . import __version__

CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  max-width:900px;margin:2em auto;padding:0 1em;color:#1a1a1a;line-height:1.5}
h1{font-size:1.6em} h2{border-bottom:2px solid #ddd;padding-bottom:.2em}
table{border-collapse:collapse;width:100%} th,td{border:1px solid #ccc;
  padding:.4em .6em;text-align:left;vertical-align:top}
th{background:#f0f0f0} code{background:#f4f4f4;padding:.1em .3em;
  border-radius:3px;word-break:break-all}
.warn{background:#fff8e1} .ok{background:#e8f5e9} .muted{color:#666}
"""

LIMITS = (
    "Honest limits: every section below is a heuristic, not proof. "
    "Secret matches are <b>candidates</b> — a flagged line may be a test "
    "fixture, an example, or a false positive; only a human who owns the "
    "repo can confirm a real secret (and if one is real, rotate it — "
    "deleting it from the repo does not un-expose it). Dependency "
    "vulnerabilities come only from the OSV database when it is reachable; "
    "when it is not, the report says so and invents nothing. "
    "Dead-code entries are modules nothing else imports — entry points, "
    "plugins, and dynamically imported modules look identical to dead code, "
    "so review before deleting anything. License detection reads file names "
    "and manifest fields only; it is not legal advice."
)


def _esc(value) -> str:
    return html.escape(str(value))


def _rows(rows: list[list[str]]) -> str:
    return "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
        for row in rows)


def build_report(target: str, result: dict, offline: bool) -> str:
    secrets = result["secrets"]
    deps = result["dependencies"]
    vulns = result["vulnerabilities"]
    licenses = result["licenses"]
    dead = result["dead_code"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if secrets:
        secret_body = (
            "<p class='warn'><b>Note:</b> these are candidate matches, "
            "not confirmed secrets. Matched values are redacted.</p>"
            "<table><tr><th>File</th><th>Line</th><th>Type</th>"
            "<th>Redacted line</th></tr>"
            + _rows([[f"<code>{_esc(s['file'])}</code>", str(s["line"]),
                      _esc(s["type"]), f"<code>{_esc(s['redacted_line'])}</code>"]
                     for s in secrets])
            + "</table>")
    else:
        secret_body = "<p class='ok'>No secret patterns found.</p>"

    if deps:
        dep_rows = []
        for dep in deps:
            key = (dep["ecosystem"], dep["name"])
            vuln_list = vulns["by_dep"].get(key, [])
            if not vulns["available"]:
                vuln_cell = ("<span class='muted'>vulnerability data "
                             "unavailable</span>")
            elif vuln_list:
                vuln_cell = "<br>".join(
                    f"<b>{_esc(v['id'])}</b>"
                    + (f" — {_esc(v['summary'])}" if v["summary"] else "")
                    for v in vuln_list)
            else:
                vuln_cell = ("<span class='muted'>no known vulnerabilities "
                             "reported by OSV for this version</span>")
            dep_rows.append([
                f"<code>{_esc(dep['name'])}</code>",
                _esc(dep["version"] or "(unpinned)"),
                _esc(dep["ecosystem"]),
                f"<code>{_esc(dep['source'])}</code>",
                vuln_cell,
            ])
        vuln_note = "" if vulns["available"] else (
            "<p class='warn'><b>Vulnerability data unavailable:</b> the OSV "
            "API could not be reached from this machine"
            + (" (offline mode was requested)." if offline else ".")
            + " No CVEs are claimed below — re-run online to check.</p>")
        dep_body = vuln_note + (
            "<table><tr><th>Dependency</th><th>Version</th><th>Ecosystem</th>"
            "<th>Manifest</th><th>Vulnerabilities (OSV)</th></tr>"
            + _rows(dep_rows) + "</table>")
    else:
        dep_body = ("<p class='muted'>No supported manifests found "
                    "(requirements.txt, package.json, go.mod, pyproject.toml, "
                    "Cargo.toml).</p>")

    lic_rows = []
    for lic_file in licenses["repo_license_files"]:
        lic_rows.append([f"<code>{_esc(lic_file['file'])}</code>",
                         _esc(lic_file["first_line"] or "(empty file)")])
    for manifest_lic in licenses["manifest_licenses"]:
        lic_rows.append([f"<code>{_esc(manifest_lic['source'])}</code> "
                         "(manifest field)",
                         _esc(manifest_lic["license"])])
    if lic_rows:
        lic_body = ("<table><tr><th>Source</th><th>License</th></tr>"
                    + _rows(lic_rows) + "</table>")
    else:
        lic_body = ""
    lic_flags = []
    if licenses["missing_repo_license"]:
        lic_flags.append(
            "<p class='warn'><b>Missing:</b> no LICENSE/COPYING file found "
            "in the repo root.</p>")
    if licenses["undeclared_manifest_license"]:
        lic_flags.append(
            "<p class='warn'><b>Unclear:</b> no license field declared in "
            "any parsed manifest.</p>")
    lic_body += "".join(lic_flags)

    if dead:
        dead_body = (
            "<p class='warn'><b>Candidates only — human review required "
            "before deleting.</b></p>"
            "<table><tr><th>File</th><th>Note</th></tr>"
            + _rows([[f"<code>{_esc(d['file'])}</code>", _esc(d["note"])]
                     for d in dead])
            + "</table>")
    else:
        dead_body = "<p class='ok'>No unused Python modules detected.</p>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>RepoDoctor report — {_esc(target)}</title>
<style>{CSS}</style></head><body>
<h1>RepoDoctor report</h1>
<p class="muted">Target: <code>{_esc(target)}</code><br>
Generated: {now} · RepoDoctor v{__version__} · read-only audit —
nothing in the target was modified.</p>
<h2>Summary</h2>
<table><tr><th>Check</th><th>Findings</th></tr>
{_rows([
    ["Secret scan (candidates)", str(len(secrets))],
    ["Dependencies inventoried", str(len(deps))],
    ["Dependencies with OSV-reported vulnerabilities",
     str(sum(len(v) for v in vulns["by_dep"].values()))
     if vulns["available"] else "unknown (OSV unreachable)"],
    ["License sources found", str(len(lic_rows))],
    ["Dead-code candidates", str(len(dead))],
])}
</table>
<h2>1 · Secrets (candidates, values redacted)</h2>
{secret_body}
<h2>2 · Dependencies &amp; vulnerabilities</h2>
{dep_body}
<h2>3 · Licenses</h2>
{lic_body}
<h2>4 · Dead code (candidates)</h2>
{dead_body}
<h2>Limits</h2>
<p>{LIMITS}</p>
</body></html>
"""
