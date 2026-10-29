# RepoDoctor v1

One command in, one HTML report out — a developer code-audit CLI built as
original glue code in the REA style: fragmented checks + one interface +
one unified report. Python standard library only. No install step, no
accounts, no keys.

## Install

None. Requires Python 3.11+ (uses `tomllib` for `pyproject.toml` /
`Cargo.toml`; on older Pythons those two manifests are skipped, everything
else still runs).

```sh
cd ~/workspace/repodoctor
```

## Usage

```sh
# Audit a LOCAL directory (never a remote URL — RepoDoctor clones nothing)
python3 -m repodoctor /path/to/a-repo

# Choose where the report goes, and/or skip the network lookup
python3 -m repodoctor /path/to/a-repo -o audit.html --offline
```

Output: one self-contained `repodoctor-report.html` (inline CSS, no
external assets) plus a short summary on stdout. Exit code 0 means the
audit ran; findings are not errors, so findings never change the exit code
(exit 2 = the path is not a directory).

## What each check does

1. **Secret scan** — regex patterns for private-key headers, AWS keys,
   GitHub/Slack tokens, secret assignments (`api_key = "..."`) and bearer
   tokens. Matches are **candidates, not confirmed secrets**, and the
   matched value is **never** written to the report: only file, line
   number, match type, and the line with the match replaced by
   `[REDACTED]`. Obvious placeholders (`example`, `changeme`, …) are
   ignored. If a flagged secret is real, rotate it — deleting it from the
   repo does not un-expose it.
2. **Dependencies** — parses `requirements.txt`, `package.json`, `go.mod`,
   `pyproject.toml`, and `Cargo.toml` into one inventory. When online,
   each pinned version is checked against the public OSV database
   (`api.osv.dev`, no key required) and real OSV-reported
   vulnerabilities are listed by ID. When OSV is unreachable (or
   `--offline` is given), the report says **"vulnerability data
   unavailable"** and claims nothing — CVEs are never invented.
   Unpinned dependencies are listed but cannot be version-checked.
3. **Licenses** — detects a `LICENSE`/`COPYING` file in the repo root
   and license fields in `package.json`, `pyproject.toml`, and
   `Cargo.toml`. Missing root license or undeclared manifest license is
   flagged. This is file/field detection, not legal advice.
4. **Dead code** — Python modules that no other file in the repo imports,
   found via `ast` import analysis. `__init__.py` files and files with a
   `__main__` guard (entry points) are excluded. Entries are
   **candidates**: scripts, plugins, and dynamically imported modules
   look identical to dead code, so review before deleting anything.

## Read-only guarantee

RepoDoctor never writes into, deletes from, or moves anything in the
audited directory. It skips `.git`, `node_modules`, virtualenvs, build
output, and binary files, and it never reads files larger than 1 MB.
The end-to-end test verifies the target is byte-identical after a run.

## Honest limits

- Heuristics, not proof: expect false positives (especially secrets and
  dead code) and false negatives (obfuscated secrets, non-Python dead
  code, private registries).
- Dead-code analysis covers Python only; JS/Go/Rust dead code is not
  attempted in v1.
- Vulnerability data covers only public OSV ecosystems for pinned
  versions; transitive dependencies are not resolved.
- No scanner binaries are called: `gitleaks`, `trufflehog`, `semgrep`,
  and `pip-audit` were checked on this VM and none is installed, so all
  checks are implemented here with stdlib regex/parsing.

## Test

```sh
python3 tests/test_end_to_end.py
```

Runs the CLI on `tests/sample-repo/` (one planted fake secret pattern,
one manifest, one unused module, one LICENSE) and verifies the report
flags the secret, the dependency, and the unused module — without ever
containing the fake secret value — and that the sample repo is unchanged
afterwards.
