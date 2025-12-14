# Results Snapshot (Template)

Paste this section into your README and update values per run.

---

## Latest Run Snapshot

**Run ID:** `<run_id>`  
**Date (Cairo):** `<YYYY-MM-DD>`  
**Model:** `<provider/model>`  
**Dataset:** SWE-bench `<subset>` / `<split>`  
**Instances evaluated:** `<N>`

### Outcome Breakdown (Harness)
- **RESOLVED:** `<n_resolved>`
- **UNRESOLVED:** `<n_unresolved>`
- **INFRA_ERROR (pre-patch):** `<n_infra_timeout>`
  - Label: `INFRA_TIMEOUT_BEFORE_PATCH`
  - Meaning: container startup/pull timed out before a valid diff was produced

### Governance Breakdown (v2)
- **OK:** `<n_ok>`
- **ABSTAIN:** `<n_abstain>`
- **VETO:** `<n_veto>`
- **Security scan failed:** `<n_scan_failed>`
- **SAD flagged:** `<n_sad_true>`

### Coverage / Accuracy (definitions)
- **Coverage:** `(# OK) / (# total - # infra_error)` = `<coverage_pct>%`
- **Accuracy (conditional on coverage):** `(# OK that are RESOLVED) / (# OK)` = `<accuracy_pct>%`

> Notes:
> - Infra errors are excluded from accuracy/coverage because no patch was produced.
> - “OK” is only emitted when strict criteria are met and no SAD/scan failure applies.

### Calibration (if enabled)
- **ECE:** `<ece_value or n/a>`
- **Reliability plot:** `artifacts/<run_id>/reliability.png`
- **Confusion matrix:** `artifacts/<run_id>/confusion_matrix.png`
- **Conformal risk control:** `<enabled/disabled>`; target α = `<alpha>`, calibrated τ = `<tau_calibrated>`

### Artifacts
- Governed eval JSONL: `swe_<run_id>_eval.V2.jsonl`
- MSA folder: `msa_<run_id>/`
  - `preds.json`
  - `exit_statuses_*.yaml`
  - `instance_results.jsonl`
