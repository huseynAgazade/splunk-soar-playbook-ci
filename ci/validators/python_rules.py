"""Structural validation rules for SOAR playbook .py files."""
from __future__ import annotations

import ast
import os
import re

# The SOAR repo that custom functions and child playbooks must live in.
# Override with SOAR_REPO_PREFIX to match your own repo name.
REPO_PREFIX = os.environ.get("SOAR_REPO_PREFIX", "soar-content") .rstrip("/") + "/"

# Lifecycle blocks that are allowed to keep their fixed names.
LIFECYCLE_BLOCKS = {"on_start", "on_finish"}

# Default auto-generated block-name patterns that must be renamed.
DEFAULT_NAME_RE = re.compile(r"^(code|format|decision|filter)_\d+$")


def _kw(call: ast.Call, name: str):
    """Return the keyword-argument node with the given name, or None."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _str(node) -> str | None:
    """Return the constant string value of a node, or None if not a literal string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dotted(func) -> str:
    """Reconstruct a dotted attribute call target, e.g. phantom.custom_function."""
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def validate_python(path: str, source: str) -> list[str]:
    """Return a list of human-readable error strings for one .py file."""
    errors: list[str] = []

    # Rule: must be valid Python.
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        return [f"{path}: invalid Python syntax at line {e.lineno}: {e.msg}"]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _dotted(node.func)
        line = node.lineno

        if target == "phantom.custom_function":
            cf = _str(_kw(node, "custom_function"))
            if cf is not None and not cf.startswith(REPO_PREFIX):
                errors.append(
                    f"{path}:{line}: phantom.custom_function custom_function="
                    f'"{cf}" must start with "{REPO_PREFIX}"'
                )
            name = _str(_kw(node, "name"))
            if name is not None and name.startswith("cs_"):
                errors.append(
                    f"{path}:{line}: phantom.custom_function name="
                    f'"{name}" must not start with "cs_"'
                )
            if name is not None and DEFAULT_NAME_RE.match(name):
                errors.append(
                    f'{path}:{line}: block name="{name}" is a default '
                    f"auto-generated name; give it a custom name"
                )

        elif target == "phantom.playbook":
            pb = _str(node.args[0]) if node.args else None
            if pb is None:
                pb = _str(_kw(node, "playbook_name"))
            if pb is not None and not pb.startswith(REPO_PREFIX):
                errors.append(
                    f"{path}:{line}: phantom.playbook "
                    f'"{pb}" must start with "{REPO_PREFIX}"'
                )

        else:
            # Generic block-name check for format/decision/filter/etc.
            name = _str(_kw(node, "name"))
            if name is not None and DEFAULT_NAME_RE.match(name):
                errors.append(
                    f'{path}:{line}: block name="{name}" is a default '
                    f"auto-generated name; give it a custom name"
                )

    # Rule: no function definitions using default names (code_1, format_2, ...).
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.name in LIFECYCLE_BLOCKS:
                continue
            if DEFAULT_NAME_RE.match(node.name):
                errors.append(
                    f"{path}:{node.lineno}: function def '{node.name}' uses a "
                    f"default auto-generated name; rename the block"
                )

    return errors
