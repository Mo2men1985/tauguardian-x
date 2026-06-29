# Limitations

TauGuardian reports review signals, not final truth.

Known limitations:

- Tests only cover the behavior they encode.
- Static checks and security heuristics can miss issues.
- Security anomaly signals can produce false positives and false negatives.
- Benchmark-style results depend on model settings, task selection, runtime
  environment, evaluator behavior, and dependency state.
- Local run artifacts can contain sensitive or noisy data and must be sanitized
  before any public sharing.

Use TauGuardian output as one part of a broader engineering review.
