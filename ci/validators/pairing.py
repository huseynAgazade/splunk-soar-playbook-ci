"""Pairing rule: a playbook must have both a .py and a .json in the repo.

When a playbook .py or .json changes, its counterpart must EXIST in the repo.
It does NOT need to be changed in the same merge request. This catches an
orphaned file (a .json with no matching .py, or vice versa) without forcing
both files to be touched every time.
"""
from __future__ import annotations

import os


def validate_pairing(changed_files: list[str], all_repo_files: set[str]) -> list[str]:
    """Return errors where a changed .py/.json has no counterpart in the repo.

    changed_files:  paths changed in this MR (py and/or json).
    all_repo_files: every tracked file in the repo (plus the changed files),
                    used to check that the counterpart exists.
    """
    errors: list[str] = []

    for path in changed_files:
        base, ext = os.path.splitext(path)
        if ext == ".py":
            counterpart = base + ".json"
        elif ext == ".json":
            counterpart = base + ".py"
        else:
            continue

        # The counterpart must exist somewhere in the repo. It does not need to
        # have been changed in this MR.
        if counterpart not in all_repo_files:
            errors.append(
                f"{path}: missing counterpart {os.path.basename(counterpart)}; "
                f"a playbook needs both its .py and .json in the repo"
            )

    return errors
