# Demo playbooks

Fixtures for exercising the pipeline. **Every credential-shaped string in here is
fabricated and authenticates nowhere.** They exist so the scanner has something
to find, and so its false positives are visible.

| Pair | Structure | Expected scan result |
|---|---|---|
| `Schedule - Demo Clean` | valid | nothing |
| `Schedule - Demo Identifier Noise` | valid | nothing — this is the false-positive test |
| `Schedule - Demo Planted Key` | valid | one API key, and the line it is passed on |
| `Schedule - Demo Secret Shapes` | valid | several distinct credential shapes |

`Demo Identifier Noise` is the important one. It is packed with strings that look
exactly like secrets and are not: condition and comparison keys, a Mattermost
channel id, a commit hash, a SHA-256 digest, a UUID node id, and a base64 blob.
A scanner that flags any of them is a scanner nobody will leave switched on.

`Demo Secret Shapes` includes cases the regex layer provably cannot reach — a
constant named `SERVICE_PASSWORD` (no word boundary before `PASSWORD`, so the
password rule misses it), a JWT split across source lines, and a token reached
through a variable rather than written inline.

To watch structure validation fail instead, break a rule on purpose — rename a
block to `code_1`, point a `phantom.custom_function` at `local/`, or put
something in `coa.data.customCode`. The scan job is skipped when validation
fails, so you will see one or the other, never both.
