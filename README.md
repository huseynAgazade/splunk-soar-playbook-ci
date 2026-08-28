# SOAR Playbook CI

CI for a Splunk SOAR playbook repository: **structural validation** of every changed
playbook, and a **two-layer credential scan** that pairs deterministic regex rules with a
local LLM. Ships as both a GitHub Actions workflow and a GitLab CI pipeline.

SOAR exports each playbook as a `.py` and a `.json`. Once a repo holds a few hundred of
them, the things that go wrong are boring and repetitive — a block still called `code_1`,
a custom function referencing the wrong repo, a description that does not match the
playbook type, a `.json` whose `.py` never got committed, a token pasted into a code block
during debugging and forgotten. None of that is caught by the platform, and all of it is
cheap to catch in a pull request.

## What it checks

### Structure — blocking

| Rule | Why |
|---|---|
| `.py` parses, `.json` parses | a half-exported playbook is worse than none |
| no default block names (`code_1`, `format_2`, `decision_3`, `filter_4`) | unnamed blocks make a run log unreadable |
| `phantom.custom_function(custom_function=...)` starts with the shared repo prefix | a CF referenced from `local/` breaks on every other instance |
| `phantom.playbook(...)` starts with the shared repo prefix | same, for child playbooks |
| block `name=` does not start with `cs_` | the CF is `cs_*`; the block that calls it should not be |
| description prefix matches `playbook_type` — `automation` → "This playbook", `data` → "This sub-playbook" | keeps generated docs coherent |
| `coa.data.customCode` is empty | playbook-level custom code hides logic outside the visual editor |
| every changed `.py` has a `.json` in the repo, and vice versa | catches an orphaned half of an export |

The counterpart does **not** have to change in the same PR — it only has to exist. That
avoids forcing both files to be touched for a one-line edit.

### Credentials — advisory

**Layer 1, deterministic.** Regex rules for private keys, AWS keys, Slack and GitHub and
GitLab tokens, Google API keys, JWTs, bearer literals, and labelled password/secret
assignments — plus a Shannon-entropy check on quoted values, but *only* on lines that also
carry a real secret keyword.

**Layer 2, Claude.** Each changed file goes to the [Messages API](https://docs.claude.com/en/api/messages)
line-numbered, with a system prompt that asks one question. The answer is constrained by
`output_config.format` to a JSON schema, so there is no JSON repair, no markdown fences to
strip and no retry-on-unparseable loop — the response either validates or the request failed.

The interesting part of both layers is the false positives. A SOAR playbook JSON is full of
things that look exactly like secrets and are not: `condition_key_f82a1f36-…`,
`comparison_key`, node ids, hashes, Mattermost `channel_id` values. So:

- the entropy trigger deliberately excludes a bare `key`, because `condition_key` is an
  identifier
- UUIDs and hex digests are skipped outright
- an allow-list of identifier keywords suppresses whole lines
- LLM findings are re-checked against the source — if the model flags a line that is an
  identifier and nothing in a ±2 line window carries a secret keyword, the finding is
  dropped, because models miscount line numbers

**Nothing that might be a secret is ever printed.** The model is told never to include the
value, and every reason string is run through a sanitizer that strips quoted spans and long
token-like runs before it reaches the log. A CI log that helpfully echoes the credential it
found is worse than no scan at all.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | clean, or the AI layer returned an unusable answer for some file (warning only) |
| `1` | a credential was found by either layer |
| `2` | the AI layer could not run — no API key, unreachable, rate limited past retries, or the request was declined |

That last one matters. An AI check that silently passes when it could not run is a check you
do not have — so a missing key, an exhausted rate limit and a safety decline all fail loudly
rather than reporting a clean file.

## Why the split

Structure validation is **blocking** and cannot be overridden — those rules are objective
and a violation is always wrong.

The credential scan is **advisory** (`continue-on-error` / `allow_failure`), because a
heuristic scanner that can hard-block a merge eventually blocks a correct one, and the fix
becomes "disable the scan". Pair it with required review and manual merge instead, so a
human decides.

## Setup

### GitHub Actions

Copy `ci/` and `.github/workflows/playbook-ci.yml` into your playbook repo.

1. Set `ANTHROPIC_API_KEY` as a repository secret. If it is an **identity-linked** key,
   also set `ANTHROPIC_WORKSPACE_ID` — without it every request returns
   `anthropic-workspace-id is required`. A workspace-scoped key needs no such header.
2. Set `SOAR_REPO_PREFIX` in the workflow to your shared repo name (default `soar-content`)
3. Make **validate-playbooks** a required status check in branch protection. Leave
   **scan-secrets** out of the required set.

Both jobs run on hosted runners; nothing needs to reach your network.

### GitLab CI

`.gitlab-ci.yml` is the original pipeline, kept in step with the Actions version. Add
`ANTHROPIC_API_KEY` as a masked CI/CD variable and register a runner tagged `soar`.

### Locally

```sh
python ci/validate_playbooks.py "Some Playbook.py" "Some Playbook.json"

pip install -r ci/requirements.txt
ANTHROPIC_API_KEY=sk-ant-... python ci/scan_secrets.py "Some Playbook.py"
```

Both take a file list, so anything that produces one — `git diff --name-only`, a
pre-commit hook — can drive them.

## Cost and model

The scan defaults to `claude-opus-5`. Override with the `CLAUDE_MODEL` env var if you want
a cheaper or faster model for this route — it is a bounded classification, so a smaller
model may well be enough for your repo.

Two things worth knowing before you turn it on for a large repo:

- **Whole files are sent, never truncated.** An exported playbook `.json` can be 100 KB, and
  you pay input tokens for all of it. A pull request touching ten large playbooks is a real,
  if small, line item — check it against your own numbers rather than assuming it is free.
- **Only changed files are scanned.** Both pipelines diff against the merge base first, so
  the cost scales with the size of the pull request, not the size of the repo.

Server-side refusal fallbacks are enabled by default, so a safety decline on a file full of
credential-shaped strings re-runs on a fallback model inside the same call instead of ending
the scan. Set `ENABLE_REFUSAL_FALLBACK = False` in `ci/scan_secrets.py` if your account has
not enabled that beta.

## Adapting the rules

Every structural rule lives in `ci/validators/`, one module per file type:

```
ci/validators/python_rules.py    AST walk over the exported .py
ci/validators/json_rules.py      description prefix, customCode
ci/validators/pairing.py         .py / .json counterpart
```

They are short and independent. The naming conventions encoded here are the ones I use;
rewrite them to yours rather than adopting mine.

## License

MIT — see [LICENSE](LICENSE).
