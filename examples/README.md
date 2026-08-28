# Demo playbooks

Two playbook pairs used to exercise the pipeline.

`Schedule - Demo Clean` passes every rule and contains nothing secret. It is the
negative control — the scan should stay quiet about it.

`Schedule - Demo Planted Key` also passes every structural rule, so validation
lets the pull request through to the scan, and carries a string shaped like an
API key. **It is not a real credential.** Both scan layers should report it.

To watch structure validation fail instead, break a rule on purpose — rename a
block to `code_1`, point a `phantom.custom_function` at `local/`, or put
something in `coa.data.customCode`. The scan job is skipped when validation
fails, so you will see one or the other, never both.
