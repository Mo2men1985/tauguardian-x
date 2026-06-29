# Sanitized Results Snapshot Template

Use this template only for sanitized aggregate summaries. Do not include raw
logs, trajectories, patches, JSONL rows, provider configuration, or credentials.

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
  - Meaning: container startup/pull timed out before a valid diff was produced.

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
> - `OK` is only emitted when strict criteria are met and no SAD/scan failure applies.

### Calibration (if enabled)
- **ECE:** `<ece_value or n/a>`
- **Reliability plot:** `runs/<run_id>/reliability.png`
- **Confusion matrix:** `runs/<run_id>/confusion_matrix.png`
- **Conformal risk control:** `<enabled/disabled>`; target alpha = `<alpha>`, calibrated tau = `<tau_calibrated>`

### Artifact Handling
- Raw governed eval JSONL remains outside source control.
- Raw runner folders remain outside source control.
- Public summaries must be aggregate, sanitized, and free of credentials or
  personal-like data.
