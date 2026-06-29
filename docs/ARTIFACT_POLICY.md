# Artifact Policy

The public repository should contain source, tests, and documentation. Generated
artifacts belong outside source control.

Disallowed committed artifacts include:

- `logs/`, `run/`, `runs/`, `eval/logs/`, `outputs/`, and `artifacts/`;
- `run_instance.log`, `test_output.txt`, and `report.json`;
- `results.jsonl`, `instance_results.jsonl`, `agentic_risk.jsonl`, and governed
  result JSONL files;
- `preds*.json` and `*.traj.json`;
- bulk `patch.diff` files;
- `__pycache__/`, `*.pyc`, and test/build caches;
- zip, rar, tar, gz, tgz, and 7z bundles.

Sanitized summaries may be documented in Markdown when they do not include
credentials, raw private data, personal-like data, or unreviewed model outputs.
