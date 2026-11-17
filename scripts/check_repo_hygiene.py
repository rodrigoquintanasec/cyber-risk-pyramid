"""Pre-publication hygiene check (no third-party dependencies). Fails (exit 1) if the files Git would publish contain data or secrets.

Usage:
  python scripts/check_repo_hygiene.py            # inside a Git repository: checks `git ls-files` (tracked + staged)
  python scripts/check_repo_hygiene.py --dir PATH # checks every file under PATH (e.g. a clean export)

It never prints a secret value: only file, line number and the kind of finding.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

FORBIDDEN_NAME = re.compile(r"(\.(sqlite|sqlite3|db|db-wal|db-shm|sqlite-wal|sqlite-shm|sqlite-journal|pem|key|pfx|p12|log)$)|(^|/)\.env$|(^|/)\.env\.(?!example$)|(^|/)backups?/|(^|/)import_tmp/|(^|/)node_modules/|(^|/)\.venv/")
ALLOWED_DATA = {"backend/data/mitre_attack.json"}
SECRET_PATTERNS = {
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "assigned secret": re.compile(r"""(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d)\b\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{20,}['"]"""),
    "NVD key (uuid)": re.compile(r"(?i)NVD_API_KEY\s*=\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
}
PERSONAL_PATH = re.compile(r"[A-Za-z]:[\\/](?:Users|Pyramid)[\\/]", re.I)
MAX_BYTES = 1_500_000
SKIP_SELF = {"scripts/check_repo_hygiene.py", "backend/tests/test_deploy.py"}


def files(root: Path, only_dir: bool) -> list[str]:
    if not only_dir:
        out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root, capture_output=True, check=True).stdout.decode("utf-8", "replace")
        return [f for f in out.split("\0") if f]
    return [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir")
    a = ap.parse_args()
    root = Path(a.dir or Path(__file__).resolve().parent.parent).resolve()
    problems: list[str] = []
    names = files(root, bool(a.dir))
    for f in names:
        if FORBIDDEN_NAME.search(f) and f not in ALLOWED_DATA:
            problems.append(f"forbidden file would be published: {f}")
            continue
        if f.startswith("backend/data/") and f not in ALLOWED_DATA:
            problems.append(f"data file would be published: {f}")
            continue
        p = root / f
        if f in SKIP_SELF or not p.is_file() or p.stat().st_size > MAX_BYTES:
            if p.is_file() and p.stat().st_size > MAX_BYTES and f not in ALLOWED_DATA and not f.endswith("package-lock.json"):
                problems.append(f"unexpectedly large file ({p.stat().st_size // 1000} KB): {f}")
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for kind, rx in SECRET_PATTERNS.items():
                if rx.search(line):
                    problems.append(f"possible {kind}: {f}:{n}")
            if PERSONAL_PATH.search(line):
                problems.append(f"absolute personal path: {f}:{n}")
    print(f"checked {len(names)} files in {root}")
    for p in problems:
        print("  PROBLEM:", p)
    print("OK" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
