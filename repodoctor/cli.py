"""RepoDoctor CLI: one command in, one HTML report out."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .report import build_report
from .scanners import run_all


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="repodoctor",
        description="Audit a LOCAL code directory and write one HTML report. "
                    "Read-only: the target is never modified.")
    parser.add_argument("path", help="path to a local repo/directory")
    parser.add_argument("-o", "--output", default="repodoctor-report.html",
                        help="report file to write (default: "
                             "./repodoctor-report.html)")
    parser.add_argument("--offline", action="store_true",
                        help="skip the OSV vulnerability lookup; report "
                             "vulnerability data as unavailable")
    parser.add_argument("--version", action="version",
                        version=f"repodoctor {__version__}")
    args = parser.parse_args(argv)

    target = os.path.abspath(args.path)
    if not os.path.isdir(target):
        print(f"repodoctor: not a directory: {args.path}", file=sys.stderr)
        return 2

    result = run_all(target, offline=args.offline)
    html_doc = build_report(args.path, result, offline=args.offline)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(html_doc)

    vuln_count = (sum(len(v) for v in result["vulnerabilities"]["by_dep"].values())
                  if result["vulnerabilities"]["available"] else None)
    vuln_line = (f"vulnerabilities: {vuln_count}"
                 if vuln_count is not None
                 else "vulnerabilities: unknown (OSV unreachable)")
    print(f"RepoDoctor: scanned {args.path}")
    print(f"  secret candidates: {len(result['secrets'])}")
    print(f"  dependencies: {len(result['dependencies'])}")
    print(f"  {vuln_line}")
    print(f"  license sources: "
          f"{len(result['licenses']['repo_license_files']) + len(result['licenses']['manifest_licenses'])}")
    print(f"  dead-code candidates: {len(result['dead_code'])}")
    print(f"  report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
