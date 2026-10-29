"""RepoDoctor: one-command code-audit glue (stdlib only).

Scans a LOCAL directory and produces one HTML report:
  1. secret scan (regex candidates, values always redacted)
  2. dependency inventory (+ best-effort OSV vulnerability lookup)
  3. license check (LICENSE file + manifest license fields)
  4. dead-code heuristic (Python modules nothing imports)

The tool is READ-ONLY on the target: it never writes into, deletes from,
or moves anything in the audited directory.
"""

__version__ = "1.0.0"
