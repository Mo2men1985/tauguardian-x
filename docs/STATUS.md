# Project Status

TauGuardian is experimental governance and evaluation tooling for coding-agent
outputs. The public repository is intended to hold source code, tests, and
documentation.

This repository is not a deployment system, a formal security approval tool, or
a regulatory assurance framework. Generated artifacts are intentionally excluded
from source control.

Current public hygiene policy:

- Keep source, tests, clean docs, and synthetic fixtures.
- Keep provider credentials and local configuration outside the repository.
- Keep run logs, trajectories, raw patches, JSONL results, and caches out of
  source control.
- Treat benchmark results as context-sensitive review signals.
