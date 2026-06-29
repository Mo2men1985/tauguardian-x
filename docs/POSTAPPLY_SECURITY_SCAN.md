# Post-Apply Full-File Delta Security Scan

The post-apply scanner is the preferred SAD mechanism for SWE-bench style local
runs. It applies a model patch on a clean worktree at the benchmark base commit
and compares full-file AST security findings before and after the patch.

> **Note:** The SWE-bench harness and these tools are intended to run on
> WSL/Linux due to Windows resource limits.

## Generate Security Reports

Smoke test on a subset:

```bash
python tg_post_apply_security_scan.py \
  --preds runs/local_example/preds.json \
  --dataset princeton-nlp/SWE-bench_Lite \
  --split test \
  --outdir runs/local_example/security_reports \
  --only example__repo-123
```

Full run (overwrites existing reports):

```bash
python tg_post_apply_security_scan.py \
  --preds runs/local_example/preds.json \
  --dataset princeton-nlp/SWE-bench_Lite \
  --split test \
  --outdir runs/local_example/security_reports \
  --force
```

Reports are written under the ignored local run directory. Do not commit raw
security reports without sanitization.

## Re-run The Analyzer With Local Reports

```bash
python analyze_mini_swe_results.py \
  --msa-dir runs/local_example \
  --output runs/local_example/eval_enriched.jsonl \
  --security-reports-dir runs/local_example/security_reports
```

When reports are present, only **new** violations trigger SAD (VETO) and scan
failures lead to ABSTAIN. The diff-fragment fallback is used only when a report
is missing.
