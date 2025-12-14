# Quickstart (WSL)

This is the reference workflow to produce reproducible SWE-bench outcomes and a governed `eval.V2.jsonl`.
Run SWE-bench **only in WSL/Linux** (native Windows is not supported due to `resource` limitations).

---

## 0) Prerequisites

- WSL2 Ubuntu (recommended)
- Docker Desktop installed on Windows with **WSL integration enabled**
- In WSL, `docker` must work for your user (`docker run --rm hello-world` succeeds)

---

## 1) Enter the repo from WSL

If your repo is on Windows, open WSL and `cd` via `/mnt/c/...`.

Example (your common path):

```bash
cd /mnt/c/Users/GIGABYTE/Downloads/tau_guardian_harness9_runtime_batched_latest/tau_guardian_harness9
```

---

## 2) Create + activate venv (WSL)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip wheel
pip install -r requirements.txt
```

Expected:
- `.venv/` created
- dependencies installed without errors

---

## 3) Preflight checks (do these before every run)

### 3A) Docker sanity
```bash
docker run --rm hello-world
```

Expected: Docker prints success and exits.

### 3B) DNS sanity (GitHub)
```bash
getent hosts raw.githubusercontent.com
curl -I https://raw.githubusercontent.com >/dev/null && echo "DNS_OK" || echo "DNS_FAIL"
```

Expected: `DNS_OK`.

If you get `DNS_FAIL`, run from Windows PowerShell:
```powershell
wsl --shutdown
```
Then reopen WSL and retry.

---

## 4) (Optional) Generate patches (costs model tokens)

Only needed if you are regenerating new patches. If you already have an `msa_<run>/` folder, skip to Step 5.

Example shape:

```bash
mini-extra swebench   --subset lite   --split test   --output msa_qwen3_coder_run21   --model dashscope/qwen3-coder-480b-a35b-instruct   --workers 1   --limit 20
```

Expected output directory:

```
msa_qwen3_coder_run21/
  preds.json
  exit_statuses_*.yaml
  trajs/...
```

---

## 5) Run SWE-bench harness evaluation (WSL/Linux only)

This step executes the patches in SWE-bench containers and writes `instance_results.jsonl`.

### Option A — Wrapper
```bash
python swe_eval_wrapper.py   --msa-dir msa_qwen3_coder_run20   --run-id qwen3_run20   --subset lite   --split test
```

### Option B — Direct CLI
```bash
python tg_swebench_cli.py   run-eval   --msa-dir msa_qwen3_coder_run20   --run-id qwen3_run20   --subset lite   --split test
```

Expected output (key artifact):
```bash
ls -lh msa_qwen3_coder_run20/instance_results.jsonl
```

---

## 6) Produce governed evaluation JSONL (free, repeatable)

This joins:
- `msa_<run>/preds.json`
- `msa_<run>/exit_statuses_*.yaml`
- `msa_<run>/instance_results.jsonl`

…and applies:
- infra failure classification (`INFRA_TIMEOUT_BEFORE_PATCH`)
- security scan `(violations, scan_failed)` with v2 semantics
- governance decision ordering (SAD→VETO; scan_failed→ABSTAIN; else strict OK; else ABSTAIN)

```bash
python analyze_mini_swe_results.py   --msa-dir msa_qwen3_coder_run20   --model-id dashscope/qwen3-coder-480b-a35b-instruct   --instance-results msa_qwen3_coder_run20/instance_results.jsonl   --output swe_qwen3_coder_run20_eval.V2.jsonl
```

Expected output:
```
swe_qwen3_coder_run20_eval.V2.jsonl
```

Sanity check counts:
```bash
python - <<'PY'
import json
from collections import Counter
p="swe_qwen3_coder_run20_eval.V2.jsonl"
c=Counter()
with open(p,encoding="utf-8") as f:
    for line in f:
        r=json.loads(line)
        c["rows"]+=1
        c["resolved_status:"+str(r.get("resolved_status"))]+=1
        c["eval_status:"+str(r.get("eval_status"))]+=1
        c["final_decision:"+str(r.get("final_decision"))]+=1
        c["infra_failure_class:"+str(r.get("infra_failure_class"))]+=1
print("\n".join(f"{k} {v}" for k,v in c.most_common()))
PY
```

---

## Expected files after a healthy run

For run folder `msa_<run>/`:

- `msa_<run>/preds.json`
- `msa_<run>/exit_statuses_*.yaml`
- `msa_<run>/instance_results.jsonl`

At repo root:

- `swe_<run>_eval.V2.jsonl`

---

## Troubleshooting (common)

- If many instances are `INFRA_TIMEOUT_BEFORE_PATCH`:
  - pre-pull SWE-bench images
  - increase container startup/pull timeout (Docker/network issue)
  - fix WSL DNS stability before reruns
