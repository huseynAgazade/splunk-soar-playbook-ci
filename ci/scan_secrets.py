#!/usr/bin/env python3.13
"""Two-layer secret scanner for SOAR playbook files.

Layer 1 (deterministic): regex + high-entropy detection for obvious secrets
    (API keys, tokens, passwords, private keys).
Layer 2 (AI): sends each changed file to a local Ollama model and asks whether
    it contains hardcoded credentials.

Exit codes:
    0  no secrets found by either layer
    1  a secret was found (regex and/or AI)
    2  AI layer failed to run (network/parse/timeout) -> HARD FAIL by request

Usage:
    scan_secrets.py <file> [<file> ...]

Environment:
    OLLAMA_URL   base URL of the Ollama server, e.g. http://ollama.internal:11434
    OLLAMA_MODEL model tag (default: qwen3.5:9b)
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3.5:9b")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))

# ---------------------------------------------------------------------------
# Layer 1: deterministic regex / entropy rules
# ---------------------------------------------------------------------------

# Each pattern targets real secrets (passwords, API keys, tokens, private keys),
# NOT identifiers like channel IDs. Patterns are intentionally conservative.
REGEX_RULES: list[tuple[str, re.Pattern]] = [
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Bearer token literal", re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}")),
    # Generic assignments (Python `key = "v"` and JSON `"key": "v"` forms).
    ("Hardcoded password", re.compile(
        r"(?i)\b(pass(?:word|wd)?|pwd)\b[\"']?\s*[=:]\s*['\"][^'\"]{4,}['\"]")),
    ("Hardcoded secret", re.compile(
        r"(?i)\b(secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b"
        r"[\"']?\s*[=:]\s*['\"][^'\"]{6,}['\"]")),
]

# Assignments whose RHS string we entropy-check (to catch unlabelled secrets).
ASSIGN_RE = re.compile(r"""['"]([A-Za-z0-9+/_=\-]{20,})['"]""")

# Allow-list substrings: things that look secret-ish but are known-safe IDs.
# Mattermost channel_id and similar identifiers should NOT trip the scanner.
ALLOWLIST_KEYS = re.compile(
    r"(?i)\b("
    r"channel_id|container_id|artifact_id|playbook_id|node_id|event_id|"
    r"case_id|incident_id|team_id|user_id|workspace_id|tenant_id|"
    r"source_id|target_id|comparison_key|condition_key|function_id|"
    r"customname|customnameid|hash|digest|id"
    r")\b\s*[=:]")

# Identifier keywords used to post-filter AI findings on a given line.
IDENTIFIER_LINE_RE = re.compile(
    r"(?i)\b("
    r"channel_id|container_id|artifact_id|playbook_id|node_id|event_id|"
    r"case_id|incident_id|team_id|user_id|workspace_id|tenant_id|"
    r"source_id|target_id|comparison_key|condition_key|function_id|hash|digest"
    r")\b")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())


# A UUID / GUID (e.g. condition_key_f82a1f36-2b25-4427-a1a8-57fc55ea5b47) is an
# identifier, not a secret. Also matches hex hashes/digests.
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEXHASH_RE = re.compile(r"^[0-9a-fA-F]{32,}$")

# Only these keywords near a value should trigger the entropy heuristic. Note we
# deliberately DO NOT include a bare "key", because condition_key / comparison_key
# / node keys in playbook JSON are identifiers, not secrets.
ENTROPY_TRIGGER_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|bearer|private[_-]?key|client[_-]?secret|credential)\b")


def regex_scan(path: str, text: str) -> list[str]:
    findings: list[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        # Skip lines that are clearly allow-listed identifiers.
        if ALLOWLIST_KEYS.search(line) or IDENTIFIER_LINE_RE.search(line):
            continue
        for label, rx in REGEX_RULES:
            if rx.search(line):
                findings.append(f"{path}:{i}: possible {label}")
        # Entropy heuristic on quoted values, only when a REAL secret keyword is
        # on the line (not a generic "key" that matches condition_key etc.).
        if ENTROPY_TRIGGER_RE.search(line):
            for m in ASSIGN_RE.finditer(line):
                val = m.group(1)
                # Ignore UUIDs and hex hashes/digests: identifiers, not secrets.
                if UUID_RE.search(val) or HEXHASH_RE.match(val):
                    continue
                if _shannon_entropy(val) >= 4.0 and len(val) >= 24:
                    findings.append(
                        f"{path}:{i}: high-entropy string near secret-like keyword "
                        f"(len={len(val)})")
    # De-duplicate while preserving order.
    seen = set()
    out = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Layer 2: Ollama AI check
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a security scanner. You are given the contents of a single SOAR "
    "playbook file (Python or JSON), with each line prefixed by its line number "
    "as 'N: '. Decide ONLY whether it contains HARDCODED CREDENTIALS: real "
    "passwords, API keys, secret keys, access tokens, bearer tokens, or private "
    "keys embedded as literal values.\n"
    "Do NOT flag: identifiers such as channel IDs, container IDs, artifact IDs, "
    "node IDs, condition/comparison keys, hashes, digests, playbook names, URLs "
    "without credentials, variable names, or references/datapaths. Only literal "
    "secret VALUES count. For example, a Mattermost 'channel_id' value like "
    "'abc123def456ghi789jkl012mn' is an identifier, NOT a credential; do not "
    "flag it.\n"
    "Do not think or explain. Never include the secret value itself in your "
    "reason; describe only its type. Respond with STRICT JSON only, no markdown. "
    "Schema:\n"
    '{"has_credentials": true|false, '
    '"findings": [{"line": <int>, "reason": "<secret type, no value>"}]}'
)


def _number_lines(text: str) -> str:
    return "\n".join(f"{i}: {ln}" for i, ln in enumerate(text.splitlines(), start=1))


def _sanitize_reason(reason: str) -> str:
    """Strip anything that could be a leaked secret from a model-provided reason.

    Removes quoted substrings and long token-like runs, so the CI log only ever
    contains a category description, never the credential value itself.
    """
    s = str(reason)
    # Remove single/double/back-quoted spans entirely.
    s = re.sub(r"([\"'`]).*?\1", "[redacted]", s, flags=re.DOTALL)
    # Redact long tokens (>= 12 chars of secret-ish alphabet) even if unquoted.
    s = re.sub(r"[A-Za-z0-9+/_=\-]{12,}", "[redacted]", s)
    # Collapse whitespace and cap length.
    s = re.sub(r"\s+", " ", s).strip()
    return s[:120] if s else "credential"


def _extract_json(s: str) -> dict | None:
    """Pull the first {...} JSON object out of a model response."""
    # Strip common thinking/markdown wrappers.
    s = re.sub(r"<think>.*?</think>", "", s, flags=re.DOTALL)
    s = s.strip()
    # Find the first balanced-looking JSON object.
    start = s.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                candidate = s[start:i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    return None
    return None


class OllamaConnectionError(RuntimeError):
    """The Ollama server could not be reached (real infrastructure failure)."""


class OllamaParseError(RuntimeError):
    """The model responded but its output could not be parsed as valid JSON."""


def ollama_scan(path: str, text: str, base_url: str) -> tuple[bool, list[str]]:
    """Return (has_credentials, findings).

    Raises OllamaConnectionError if the server is unreachable, or
    OllamaParseError if the model's response can't be parsed. Retries a parse
    failure once before giving up.
    """
    url = base_url.rstrip("/") + "/api/chat"
    numbered = _number_lines(text)
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "think": False,  # disable thinking -> faster, fewer stray tokens
        "format": "json",  # ask Ollama to constrain output to valid JSON
        "options": {
            "temperature": 0,
            "num_predict": 512,  # cap generation; the JSON answer is small
        },
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"FILE: {path}\n\n{numbered}"},
        ],
    }
    data = json.dumps(payload).encode("utf-8")

    last_parse_err: Exception | None = None
    for attempt in (1, 2):  # one retry on parse failure
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
                body = resp.read().decode("utf-8")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            raise OllamaConnectionError(f"Ollama unreachable for {path}: {e}") from e

        try:
            outer = json.loads(body)
            content = outer["message"]["content"]
        except (json.JSONDecodeError, KeyError) as e:
            last_parse_err = e
            continue

        parsed = _extract_json(content)
        if parsed is None or "has_credentials" not in parsed:
            last_parse_err = ValueError("model JSON missing has_credentials")
            continue

        # Success.
        return _build_findings(path, text, parsed)

    # Both attempts failed to parse.
    raise OllamaParseError(
        f"Could not parse model JSON for {path} after retry "
        f"(response redacted to avoid leaking secrets).")


def _build_findings(path: str, text: str, parsed: dict) -> tuple[bool, list[str]]:
    has = bool(parsed.get("has_credentials"))
    raw_findings = parsed.get("findings") or []
    if not isinstance(raw_findings, list):
        raw_findings = [raw_findings]

    src_lines = text.splitlines()

    _SECRET_KW = re.compile(
        r"(?i)\b(pass(?:word|wd)?|pwd|secret|api[_-]?key|apikey|"
        r"access[_-]?token|auth[_-]?token|bearer|private[_-]?key|"
        r"client[_-]?secret)\b")

    def _line_is_identifier(line: str) -> bool:
        return bool(IDENTIFIER_LINE_RE.search(line)) and not bool(_SECRET_KW.search(line))

    def _is_false_positive(line_no, reason_text: str) -> bool:
        """Drop findings that are really identifiers, not secrets.

        Robust to the model reporting a slightly wrong line number: we check the
        reported line, a small window around it, and the model's own reason text.
        """
        reason = str(reason_text or "")

        # 1) Reason text itself names an identifier (e.g. "channel_id") and no secret.
        if IDENTIFIER_LINE_RE.search(reason) and not _SECRET_KW.search(reason):
            return True

        # 2) Check the reported line and a +/-2 window (models miscount lines).
        if isinstance(line_no, int) and 1 <= line_no <= len(src_lines):
            lo = max(1, line_no - 2)
            hi = min(len(src_lines), line_no + 2)
            window = src_lines[lo - 1:hi]
            # If ANY line in the window has a real secret keyword, keep the finding.
            if any(_SECRET_KW.search(l) for l in window):
                return False
            # Otherwise, if the exact line is an identifier line, drop it.
            if _line_is_identifier(src_lines[line_no - 1]):
                return True

        return False

    findings: list[str] = []
    for f in raw_findings:
        if isinstance(f, dict):
            line = f.get("line")
            reason_raw = f.get("reason", "credential")
            if _is_false_positive(line, reason_raw):
                continue
            reason = _sanitize_reason(reason_raw)
            loc = f"{path}:{line}" if line is not None else path
            findings.append(f"{loc}: AI: {reason}")
        else:
            if _is_false_positive(None, str(f)):
                continue
            findings.append(f"{path}: AI: {_sanitize_reason(str(f))}")

    # If all AI findings were filtered out as identifiers, this file is clean.
    has = has and len(findings) > 0
    return has, findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    files = [a for a in argv if a.strip()]
    if not files:
        print("No files to scan.")
        return 0

    base_url = os.environ.get("OLLAMA_URL", "").strip()
    if not base_url:
        print("ERROR: OLLAMA_URL is not set; cannot run AI secret scan.", file=sys.stderr)
        return 2  # hard fail: AI layer unavailable

    regex_findings: list[str] = []
    ai_findings: list[str] = []
    ai_unreachable = False   # connection failure -> hard fail
    ai_parse_warnings: list[str] = []  # model returned junk -> warn only

    for path in files:
        p = Path(path)
        if not p.exists():
            continue
        if p.suffix.lower() not in (".py", ".json"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")

        # Layer 1
        regex_findings.extend(regex_scan(path, text))

        # Layer 2
        try:
            has, findings = ollama_scan(path, text, base_url)
            if has:
                ai_findings.extend(findings or [f"{path}: AI flagged credentials"])
        except OllamaConnectionError as e:
            print(f"  ! {e}", file=sys.stderr)
            ai_unreachable = True
        except OllamaParseError as e:
            # Model responded but output was unusable. Do not hard-fail on this;
            # the regex layer still ran. Warn so a human can eyeball the file.
            print(f"  ~ {e}", file=sys.stderr)
            ai_parse_warnings.append(f"{path}: AI could not analyze (unparseable response)")

    print("=" * 50)
    if regex_findings:
        print("Regex/entropy layer findings:")
        for f in regex_findings:
            print(f"  ✗ {f}")
    else:
        print("Regex/entropy layer: clean.")

    if ai_findings:
        print("\nAI layer findings:")
        for f in ai_findings:
            print(f"  ✗ {f}")
    elif not ai_unreachable and not ai_parse_warnings:
        print("AI layer: clean.")

    if ai_parse_warnings:
        print("\nAI layer warnings (not blocking):")
        for w in ai_parse_warnings:
            print(f"  ~ {w}")
    print("=" * 50)

    # Decide exit code.
    # Connection failure to Ollama is a real infra problem -> hard fail.
    if ai_unreachable:
        print("\nSecret scan FAILED: Ollama server unreachable (hard fail).")
        return 2
    # Any actual finding (regex or AI) -> fail (advisory in CI via allow_failure).
    if regex_findings or ai_findings:
        n = len(regex_findings) + len(ai_findings)
        print(f"\nSecret scan FOUND {n} potential credential(s).")
        return 1
    # Parse warnings alone do not fail the job.
    if ai_parse_warnings:
        print("\nSecret scan passed with warnings (some files not AI-analyzed).")
        return 0

    print("\nSecret scan passed: no credentials detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
