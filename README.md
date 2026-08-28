# SOAR Playbook CI

Structure validation and credential scanning for a SOAR playbook repository, on
every pull request. Ships as a GitHub Actions workflow and a GitLab CI pipeline.

![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.13-blue)

SOAR exports each playbook as a `.py` and a `.json`. Once a repo holds a few hundred of
them, the things that go wrong are boring and repetitive — a block still called `code_1`, a
custom function pointing at the wrong repo, a description that does not match the playbook
type, a `.json` whose `.py` never got committed, a token pasted into a code block during
debugging and forgotten. The platform catches none of it, and all of it is cheap to catch in
a pull request.

## What a run looks like

Structure first. This is the real output from the fixtures in `examples/`:

```
Playbook validation passed (4 file(s) checked).
```

Then the credential scan, on a playbook carrying fabricated secrets:

```
Regex/entropy layer findings:
  x Demo Secret Shapes.py:9:  possible AWS access key id
  x Demo Secret Shapes.py:10: possible Slack token
  x Demo Secret Shapes.py:12: possible Bearer token literal
  x Demo Secret Shapes.json:19: possible Hardcoded secret

AI layer findings:
  x Demo Secret Shapes.py:9:  AI: Hardcoded AWS access key ID literal
  x Demo Secret Shapes.py:10: AI: Hardcoded Slack bot/webhook token literal
  x Demo Secret Shapes.py:11: AI: Hardcoded service password literal
  x Demo Secret Shapes.py:12: AI: Hardcoded bearer token literal
  x Demo Secret Shapes.py:13: AI: Hardcoded JWT session token assembled from string literals
  x Demo Secret Shapes.json:19: AI: Hardcoded API key literal in node config
```

Two of those the regex layer cannot reach. Line 11 is a constant named
`SERVICE_PASSWORD` — underscore is a word character, so `\bpassword\b` never matches it,
and `DB_PASSWORD` slips through the same way. Line 13 is a JWT concatenated across four
source lines, so no single line contains one.

And on a playbook stuffed with condition keys, comparison keys, a channel id, a commit
hash, a SHA-256 digest, a UUID and a base64 blob — **both layers report nothing.** That is
the result that decides whether anyone leaves the scan switched on.

## Quick start

Copy `ci/` and `.github/workflows/playbook-ci.yml` into your playbook repo:

```sh
git clone --depth 1 https://github.com/huseynAgazade/soar-playbook-ci /tmp/tpl
cp -r /tmp/tpl/ci /tmp/tpl/.github .
git add ci .github && git commit -m "Add playbook CI" && git push
```

Then:

1. Add `ANTHROPIC_API_KEY` as a repository secret. Scope the key to **one workspace** — an
   "all workspaces" key is identity-linked and every request will return
   `anthropic-workspace-id is required` unless you also set `ANTHROPIC_WORKSPACE_ID`.
2. Set `SOAR_REPO_PREFIX` in the workflow to your shared repo name (default `soar-content`).
3. Make **validate-playbooks** a required status check in branch protection. Leave
   **scan-secrets** out of the required set.

Both jobs run on hosted runners; nothing needs to reach your network.

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

The counterpart does **not** have to change in the same pull request — it only has to exist.
That avoids forcing both files to be touched for a one-line edit.

### Credentials — advisory

**Layer 1, deterministic.** Regex rules for private keys, AWS keys, Slack, GitHub and GitLab
tokens, Google API keys, JWTs, bearer literals, and labelled password/secret assignments,
plus a Shannon-entropy check on quoted values — but only on lines that also carry a real
secret keyword.

**Layer 2, Claude.** Each changed file goes to the [Messages API](https://docs.claude.com/en/api/messages)
line-numbered, with a system prompt that asks one question. The answer is constrained by
`output_config.format` to a JSON schema, so there is no JSON repair, no markdown fences to
strip and no retry-on-unparseable loop — the response either validates or the request failed.

### The false positives are the hard part

A SOAR playbook JSON is full of things that look exactly like secrets and are not:
`condition_key_f82a1f36-…`, `comparisonKey`, node ids, `customNameId` hex blobs, commit
hashes, Mattermost channel ids. A scanner that flags those is a scanner someone will switch
off within a week. So:

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
do not have, so a missing key, an exhausted rate limit and a safety decline all fail loudly
rather than reporting a clean file. The first such failure stops further API calls — the next
file would hit it identically — while the regex layer finishes the run.

## Why the split

Structure validation is **blocking** and cannot be overridden. Those rules are objective and
a violation is always wrong.

The credential scan is **advisory** (`continue-on-error` / `allow_failure`), because a
heuristic scanner that can hard-block a merge eventually blocks a correct one, and the fix
becomes "disable the scan". Pair it with required review and manual merge instead, so a
human decides.

The jobs run in order, not in parallel: `scan-secrets` declares `needs: validate-playbooks`,
so a pull request that fails structure validation is never sent to the API. It cannot merge
anyway, and the scan is the part that costs money.

## Cost and model

The scan defaults to `claude-opus-5`; override with `CLAUDE_MODEL`. It is a bounded
classification, so a smaller model may well be enough for your repo.

- **Whole files are sent, never truncated.** An exported playbook `.json` can be 100 KB and
  you pay input tokens for all of it. Check it against your own numbers rather than assuming
  it is free.
- **Only changed files are scanned.** Both pipelines diff against the merge base first, so
  cost scales with the size of the pull request, not the size of the repo.

Server-side refusal fallbacks are on by default, so a safety decline on a file full of
credential-shaped strings re-runs on a fallback model inside the same call instead of ending
the scan. Set `ENABLE_REFUSAL_FALLBACK = False` in `ci/scan_secrets.py` if your account has
not enabled that beta.

## GitLab CI

`.gitlab-ci.yml` is the original pipeline, kept in step with the Actions version. Add
`ANTHROPIC_API_KEY` as a masked CI/CD variable and register a runner tagged `soar`. GitLab
stages are sequential, so the scan already waits for validation there.

## Running it locally

```sh
python ci/validate_playbooks.py "Some Playbook.py" "Some Playbook.json"

pip install -r ci/requirements.txt
ANTHROPIC_API_KEY=sk-ant-... python ci/scan_secrets.py "Some Playbook.py"
```

Both take a file list, so anything that produces one — `git diff --name-only`, a pre-commit
hook — can drive them.

## Adapting the rules

```
ci/validators/python_rules.py    AST walk over the exported .py
ci/validators/json_rules.py      description prefix, customCode
ci/validators/pairing.py         .py / .json counterpart
```

Short and independent. The conventions encoded here are the ones I use; rewrite them to
yours rather than adopting mine.

`examples/` holds four fixture pairs used to exercise the pipeline. **Every
credential-shaped string in them is fabricated and authenticates nowhere** — they exist so
the scanner has something to find and so its false positives are visible.

## License

MIT — see [LICENSE](LICENSE).
