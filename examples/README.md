# Demo playbooks

Two playbook pairs used to exercise the pipeline.

`Schedule - Demo Clean` passes every rule.

`Schedule - Demo Broken` breaks four structural rules and carries a planted
string shaped like an API key. **It is not a real credential** — it exists so the
secret scan has something to find. Open a pull request that changes either file
to see the checks run.
