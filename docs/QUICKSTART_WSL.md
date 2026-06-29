# Quickstart For Local SWE-Bench Style Runs

This workflow is for local experimentation. Keep generated outputs outside the
public source tree or under ignored directories such as `runs/`.

## Prerequisites

- Linux or WSL2.
- Docker available to the active user.
- A Python virtual environment.
- Any provider credentials supplied through a private shell environment or secret
  store.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip wheel
```

Install only the dependencies needed for the workflow you intend to run.

## Preflight Checks

```bash
docker run --rm hello-world
python -m pytest
```

## Optional External Agent Run

If you use an external SWE-bench style runner, write outputs to an ignored
directory:

```bash
mkdir -p runs/local_example
```

Provider configuration should live outside the repository. For the helper script
in this repo, set:

```bash
export TAUGUARDIAN_SWEBENCH_CONFIG=/path/to/private/config.yaml
export TAUGUARDIAN_MODEL_ID=provider/model-name
```

Then run:

```bash
./e2e_swebench_pipeline.sh astropy__astropy-12907
```

Review and sanitize any generated summaries before sharing them. Do not commit
raw logs, trajectories, patches, reports, JSONL outputs, or provider configs.

## Analyze Existing Local Outputs

Analyzer commands may read local generated files, but their outputs should remain
under ignored directories:

```bash
python analyze_mini_swe_results.py \
  --msa-dir runs/local_example \
  --output runs/local_example/eval_enriched.jsonl
```

See `docs/ARTIFACT_POLICY.md` before publishing any result summary.
