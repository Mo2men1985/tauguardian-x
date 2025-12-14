# τGuardian

τGuardian is a governance and evaluation harness for SWE-bench style coding
agents. The harness can wrap external agents (like mini-SWE-agent) and compute
τ metrics, CRI, and SAD security signals over their outputs.

## SWE-bench with mini-SWE-agent + Gemini 2.5 Pro (Option 1)

τGuardian's native SWE harness (`run_swebench_experiment.py` / `swe_runner.py`) is model-agnostic and works
with any LLM configured via `llm_client.py`. For Gemini 2.5 Pro / Gemini 3 Pro benchmarks on SWE-bench,
a practical path is to re-use the official **mini-SWE-agent** pipeline and treat τGuardian as an extra
metrics layer around its results.

See `docs/POSTAPPLY_SECURITY_SCAN.md` for the authoritative post-apply security
scan workflow that stabilizes SAD decisions on SWE-bench outputs.

This repository does **not** vendor mini-SWE-agent. To reproduce the Gemini 2.5 Pro numbers from the
SWE-bench leaderboard:

1. Install `mini-swe-agent` and its dependencies in a separate environment, following the official docs:
   - https://github.com/SWE-agent/mini-swe-agent
   - https://mini-swe-agent.com/latest/

2. Configure Gemini via LiteLLM or the provider config used by mini-SWE-agent, and run their official
   SWE-bench command for `gemini-2.5-pro` or `gemini-2.5-flash`.

3. Export the predictions JSONL / results produced by mini-SWE-agent.

4. Optionally, you can then point τGuardian at those patched repos (or the predictions file) and run:
   - `python analyze_results.py` to compute CRI / SAD / τ-style metrics or compare against τGuardian's
     own SWE harness.

This keeps τGuardian's runtime simple and provider-agnostic, while allowing you to rely on the
battle-tested mini-SWE-agent stack for the exact Gemini SWE-bench configuration used on the public
leaderboard.
