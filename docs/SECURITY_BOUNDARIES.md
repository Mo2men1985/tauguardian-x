# Security And Data Boundaries

TauGuardian source control must not contain real credentials or raw generated
run artifacts.

Do not commit:

- `.env` or `.env.local` files;
- provider API keys or local provider configuration;
- command transcripts that set or echo credentials;
- logs, trajectories, patch dumps, reports, or JSONL result dumps;
- personal data, client data, or live operational data;
- archive bundles that may contain any of the above.

Examples must use obvious placeholders such as `YOUR_API_KEY`. Provider keys
should be supplied through a private shell environment, a CI secret store, or a
local secret manager.

TauGuardian's security checks are heuristics. They are useful for review, but
they do not certify code as secure.
