# TauGuardian

TauGuardian is an experimental governance and evaluation harness for coding-agent
outputs. It helps structure tests, static checks, security anomaly signals, and
reproducibility workflows so generated code changes can be reviewed more
consistently.

## Status

This repository is a public canonical source tree for TauGuardian. It is intended
to contain source code, tests, and documentation only.

Run logs, raw benchmark outputs, trajectories, patch dumps, local configuration,
provider credentials, and generated caches are intentionally excluded from source
control. The project is research and evaluation tooling, not a production
deployment system.

## What This Is

TauGuardian provides scripts and checks for evaluating coding-agent outputs. It
can help organize:

- task definitions and candidate outputs;
- unit tests and static checks;
- security anomaly heuristics;
- bounded evaluation and repair workflows;
- reproducibility notes for local experiments.

## What This Is Not

TauGuardian is not:

- a formal security approval tool;
- a regulatory assurance system;
- a deployment safety guarantee;
- a model-ranking claim;
- a place to store raw run logs, trajectories, generated outputs, or provider
  credentials.

## Why It Exists

Coding-agent outputs can be difficult to review consistently. TauGuardian exists
to make review boundaries more explicit: what was checked, which signals were
collected, what was skipped, and which artifacts should remain outside the public
source tree.

## Core Concepts

- **CRI**: a reliability/coherence signal based on checks such as tests and
  static analysis.
- **SAD**: a security anomaly signal for suspicious generated-code patterns.
- **Tau**: a bounded evaluation or repair depth.
- **Decision policy**: a conservative OK, abstain, or veto interpretation of
  available signals.

These signals are heuristics. They support review; they do not replace expert
engineering or security judgment.

## How It Works

At a high level, TauGuardian accepts task definitions and candidate code changes,
then applies a combination of tests, static checks, and security heuristics. Any
generated outputs should be written to local ignored directories such as `runs/`
or external artifact storage, not committed to this repository.

## Installation

Use a local Python environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
```

Install project dependencies according to the scripts you intend to run. When a
provider key is required for an external tool, set it through your shell or a
private secret store. Do not write real provider keys into repository files.

## Running Tests

Run the test suite from the repository root:

```powershell
python -m pytest
```

Some optional integration workflows may require external tools or datasets. Keep
their outputs outside the repository tree.

## Reproducibility

For reproducible local runs:

- record tool versions and command arguments in local notes outside source
  control;
- use deterministic synthetic fixtures where practical;
- write generated artifacts under ignored directories such as `runs/`;
- publish only sanitized summaries when sharing results.

See `docs/REPRODUCIBILITY.md` and `docs/ARTIFACT_POLICY.md` for the repository
rules.

## Security And Data Boundaries

Never commit real API keys, `.env` files, local provider configs, logs,
trajectories, patch dumps, personal data, or client data. Examples must use
obvious placeholders only.

See `docs/SECURITY_BOUNDARIES.md` and `docs/CONFIGURATION.md`.

## Limitations

TauGuardian uses tests and heuristics. It can miss bugs, security issues, and
context-specific risks. Benchmark-style results are sensitive to task selection,
runtime environment, model configuration, and evaluator behavior. Treat all
outputs as review signals, not final judgments.

## Roadmap

- Keep the public repository source/docs/tests only.
- Expand synthetic task coverage.
- Improve artifact hygiene checks.
- Document reproducible local evaluation workflows.
- Evaluate whether a separate sanitized research-harness repo is useful.

## License

This project is distributed under the license in `LICENSE`.
