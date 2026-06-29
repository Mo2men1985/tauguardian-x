# Reproducibility

Reproducible local runs should separate source code from generated artifacts.

Recommended practice:

1. Record the command, tool versions, model identifier, and dataset identifier in
   local notes or sanitized summaries.
2. Write run outputs under ignored directories such as `runs/`.
3. Keep raw logs, trajectories, patch diffs, and JSONL outputs out of Git.
4. Use synthetic fixtures for tests and docs.
5. Publish only sanitized aggregate summaries when results need to be shared.

If an external benchmark or agent runner is used, follow that tool's official
installation instructions and keep its workspace outside the public source tree
unless the files are reviewed and intentionally committed.
