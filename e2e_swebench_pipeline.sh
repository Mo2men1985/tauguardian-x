#!/usr/bin/env bash
set -euo pipefail

INSTANCE_ID=${1:-astropy__astropy-12907}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_BASE="runs/e2e_${INSTANCE_ID}_${TIMESTAMP}"
CONFIG_PATH=${TAUGUARDIAN_SWEBENCH_CONFIG:-}
MODEL_ID=${TAUGUARDIAN_MODEL_ID:-}

if [[ -z "$CONFIG_PATH" ]]; then
  echo "[ERROR] Set TAUGUARDIAN_SWEBENCH_CONFIG to a private config file path." >&2
  echo "[ERROR] Do not commit provider configs or API keys to this repository." >&2
  exit 2
fi

if [[ -z "$MODEL_ID" ]]; then
  echo "[ERROR] Set TAUGUARDIAN_MODEL_ID to the private provider/model id for this run." >&2
  exit 2
fi

mkdir -p "$OUT_BASE"

echo "[STEP] Running mini-extra swebench for $INSTANCE_ID"
mini-extra swebench \
  --subset lite \
  --split test \
  --filter "$INSTANCE_ID" \
  --config "$CONFIG_PATH" \
  --output "$OUT_BASE" \
  --model "$MODEL_ID" \
  --workers 1

echo "[STEP] Extracting predictions from trajectories"
python mini_swe_extract_from_traj.py --run-dir "$OUT_BASE"

echo "[STEP] Running SWE-bench evaluation"
python swe_eval_wrapper.py \
  --predictions-path "$OUT_BASE/preds_filled.json" \
  --run-id "e2e_${INSTANCE_ID}_${TIMESTAMP}" \
  --outdir "$OUT_BASE/eval" \
  --timeout 1800

echo "[STEP] Running post-apply security scan"
python tg_post_apply_security_scan.py \
  --preds "$OUT_BASE/preds_filled.json" \
  --dataset princeton-nlp/SWE-bench_Lite \
  --split test \
  --outdir "$OUT_BASE/security_reports" \
  --force

echo "[STEP] Analyzing results and risk/coverage"
python analyze_mini_swe_results.py \
  --msa-dir "$OUT_BASE" \
  --instance-results "$OUT_BASE/eval/instance_results.jsonl" \
  --model-id "$MODEL_ID" \
  --output "$OUT_BASE/eval_enriched.jsonl" \
  --security-reports-dir "$OUT_BASE/security_reports"

python tg_risk_coverage.py --jsonl "$OUT_BASE/eval_enriched.jsonl"
