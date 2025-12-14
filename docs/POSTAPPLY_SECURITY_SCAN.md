# Post-Apply Full-File Delta Security Scan

The post-apply scanner is the authoritative SAD mechanism for SWE-bench runs. It
applies the model patch on a clean worktree at the SWE-bench base commit and
compares full-file AST security findings before and after the patch.

> **Note:** The SWE-bench harness and these tools are intended to run on
> WSL/Linux due to Windows resource limits.

## Generate security reports

Smoke test on a subset:

```bash
python tg_post_apply_security_scan.py \
  --preds msa_outputs/preds.json \
  --dataset princeton-nlp/SWE-bench_Lite \
  --split test \
  --outdir msa_outputs/security_reports \
  --only example__repo-123
```

Full run (overwrites existing reports):

```bash
python tg_post_apply_security_scan.py \
  --preds msa_outputs/preds.json \
  --dataset princeton-nlp/SWE-bench_Lite \
  --split test \
  --outdir msa_outputs/security_reports \
  --force
```

Reports are written to `msa_outputs/security_reports/<instance_id>.json` with
scope `postapply_fullfile_delta_v1`.

## Re-run the analyzer with authoritative reports

```bash
python analyze_mini_swe_results.py \
  --msa-dir msa_outputs \
  --output swe_results.jsonl \
  --security-reports-dir msa_outputs/security_reports
```

When reports are present, only **new** violations trigger SAD (VETO) and scan
failures lead to ABSTAIN. The diff-fragment fallback is used only when a report
is missing.
