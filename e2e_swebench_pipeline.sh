#!/usr/bin/env bash
set -euo pipefail

INSTANCE_ID=${1:-astropy__astropy-12907}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_BASE="runs/e2e_${INSTANCE_ID}_${TIMESTAMP}"

mkdir -p "$OUT_BASE"

echo "[STEP] Running mini-extra swebench for $INSTANCE_ID"
mini-extra swebench \
  --subset lite \
  --split test \
  --filter "$INSTANCE_ID" \
  --config swebench_groq.yaml \
  --output "$OUT_BASE" \
  --model "groq/meta-llama/llama-4-scout-17b-16e-instruct" \
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
  --model-id "groq/meta-llama/llama-4-scout-17b-16e-instruct" \
  --output "$OUT_BASE/eval_enriched.jsonl" \
  --security-reports-dir "$OUT_BASE/security_reports"

python tg_risk_coverage.py --jsonl "$OUT_BASE/eval_enriched.jsonl"
