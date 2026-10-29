"""End-to-end test: run the CLI on tests/sample-repo and verify the report.

Checks:
  1. The planted fake secret pattern is flagged (file + type present).
  2. The fake secret VALUE never appears in the report (redaction).
  3. The requirements.txt dependency is inventoried.
  4. The unused module is flagged as a dead-code candidate.
  5. The LICENSE file is detected.
  6. Offline mode reports vulnerability data as unavailable (never invented).
  7. The target directory is byte-identical after the run (read-only).

Run:  python3 tests/test_end_to_end.py
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_REPO = os.path.join(PROJECT_ROOT, "tests", "sample-repo")
FAKE_SECRET = "sk-test-9f8e7d6c5b4a3210"

failures = []


def check(label: str, condition: bool) -> None:
    print(("PASS " if condition else "FAIL ") + label)
    if not condition:
        failures.append(label)


def snapshot(root: str) -> dict:
    result = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(dirnames)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            with open(full, "rb") as fh:
                result[os.path.relpath(full, root)] = hashlib.sha256(
                    fh.read()).hexdigest()
    return result


def main() -> int:
    before = snapshot(SAMPLE_REPO)
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "report.html")
        proc = subprocess.run(
            [sys.executable, "-m", "repodoctor", SAMPLE_REPO,
             "--offline", "-o", report],
            cwd=PROJECT_ROOT, capture_output=True, text=True)
        print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
        check("CLI exits 0", proc.returncode == 0)
        check("report file written", os.path.isfile(report))
        if not os.path.isfile(report):
            print("FAILED: no report to inspect")
            return 1
        with open(report, encoding="utf-8") as fh:
            html_doc = fh.read()

    check("secret flagged: main.py present", "main.py" in html_doc)
    check("secret flagged: assignment type present",
          "Generic secret assignment" in html_doc)
    check("secret value NOT in report (redacted)", FAKE_SECRET not in html_doc)
    check("redaction marker present", "[REDACTED]" in html_doc)
    check("dependency inventoried: requests", "requests" in html_doc)
    check("dead-code candidate flagged: orphan.py", "orphan.py" in html_doc)
    check("entry point NOT flagged as dead: main.py not in dead section",
          html_doc.split("Dead code (candidates)")[1].count("main.py") == 0)
    check("LICENSE detected", "LICENSE" in html_doc)
    check("offline: vulnerability data unavailable stated",
          "vulnerability data unavailable" in html_doc)
    check("no invented CVE ids in offline report", "CVE-" not in html_doc)
    check("target unchanged after run (read-only)",
          snapshot(SAMPLE_REPO) == before)

    if failures:
        print(f"\n{len(failures)} check(s) FAILED")
        return 1
    print("\nAll end-to-end checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
