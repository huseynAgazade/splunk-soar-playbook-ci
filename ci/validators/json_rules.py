"""Structural validation rules for SOAR playbook .json files."""
from __future__ import annotations

import json

DESCRIPTION_PREFIX = {
    "data": "This sub-playbook",
    "automation": "This playbook",
}


def validate_json(path: str, source: str) -> list[str]:
    """Return a list of human-readable error strings for one .json file."""
    errors: list[str] = []

    # Rule: must be valid JSON.
    try:
        doc = json.loads(source)
    except json.JSONDecodeError as e:
        return [f"{path}: invalid JSON at line {e.lineno} col {e.colno}: {e.msg}"]

    coa = doc.get("coa") or {}
    data = coa.get("data") or {}

    # Rule: description prefix depends on playbook_type.
    playbook_type = coa.get("playbook_type")
    description = (data.get("description") or "")
    expected_prefix = DESCRIPTION_PREFIX.get(playbook_type)
    if expected_prefix is not None:
        if not description.startswith(expected_prefix):
            errors.append(
                f'{path}: playbook_type="{playbook_type}" requires description '
                f'to start with "{expected_prefix}" '
                f'(found: "{description[:40]}...")'
            )
    elif playbook_type is not None:
        # Unknown playbook_type; surface it rather than silently pass.
        errors.append(
            f'{path}: unknown playbook_type "{playbook_type}" '
            f"(expected 'data' or 'automation')"
        )

    # Rule: coa.data.customCode must be empty/null (no custom code at playbook level).
    custom_code = data.get("customCode")
    if isinstance(custom_code, str) and len(custom_code) > 0:
        errors.append(
            f"{path}: coa.data.customCode must be empty; "
            f"found {len(custom_code)} chars of custom code"
        )

    return errors
