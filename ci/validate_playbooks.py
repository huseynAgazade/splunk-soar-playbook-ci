#!/usr/bin/env python3.13
"""Entry point for SOAR playbook structural validation in GitLab CI.

Usage:
    validate_playbooks.py <changed_file> [<changed_file> ...]

Reads the given changed files, applies the Python / JSON / pairing rules, and
exits non-zero if any rule is violated. Intended to be fed the list of files
changed in a merge request.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Enforce that the validator itself runs on Python 3.13.
if sys.version_info[:2] != (3, 13):
    sys.stderr.write(
        f"ERROR: this validator must run on Python 3.13, "
        f"found {sys.version_info.major}.{sys.version_info.minor}\n"
    )
    sys.exit(2)

# Allow running as a script (python ci/validate_playbooks.py) by ensuring the
# ci/ directory is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validators import validate_python, validate_json, validate_pairing  # noqa: E402


def repo_tracked_files() -> set[str]:
    """Return every git-tracked file path (used for pairing counterpart checks)."""
    import subprocess

    try:
        out = subprocess.run(
            ["git", "ls-files"],
            capture_output=True, text=True, check=True,
        )
        return set(out.stdout.splitlines())
    except Exception:
        # If git isn't available, fall back to filesystem existence checks only.
        return set()


def main(argv: list[str]) -> int:
    changed_files = [a for a in argv if a.strip()]
    if not changed_files:
        print("No changed files to validate.")
        return 0

    all_errors: list[str] = []

    # Per-file content rules.
    # In diff mode (CI), a listed file may be legitimately absent because it was
    # deleted in the merge request -> skip it. In direct mode (local testing),
    # a missing path is almost always a typo -> hard error.
    from_diff = "--from-diff" in argv
    changed_files = [a for a in changed_files if a != "--from-diff"]
    if not changed_files:
        print("No changed files to validate.")
        return 0

    all_errors: list[str] = []
    checked = 0

    # Per-file content rules.
    for path in changed_files:
        p = Path(path)
        if not p.exists():
            if from_diff:
                # Deleted file in the MR; nothing to validate.
                continue
            all_errors.append(f"{path}: file not found")
            continue
        suffix = p.suffix.lower()
        if suffix == ".py":
            all_errors.extend(validate_python(path, p.read_text(encoding="utf-8")))
            checked += 1
        elif suffix == ".json":
            all_errors.extend(validate_json(path, p.read_text(encoding="utf-8")))
            checked += 1
        else:
            all_errors.append(
                f"{path}: unsupported file type '{suffix or p.name}' "
                f"(expected .py or .json)"
            )

    # Cross-file pairing rule.
    tracked = repo_tracked_files()
    # Include changed files themselves in case they are newly added.
    tracked |= set(changed_files)
    all_errors.extend(validate_pairing(changed_files, tracked))

    if all_errors:
        print("Playbook validation FAILED:\n")
        for err in all_errors:
            print(f"  ✗ {err}")
        print(f"\n{len(all_errors)} problem(s) found.")
        return 1

    print(f"Playbook validation passed ({len(changed_files)} file(s) checked).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
