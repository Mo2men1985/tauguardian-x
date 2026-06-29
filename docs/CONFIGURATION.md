# Configuration

TauGuardian reads provider credentials from private environment variables or
external secret stores. Do not commit real provider keys or local configuration
files.

Use obvious placeholders in documentation:

```powershell
$env:TAUGUARDIAN_PROVIDER_KEY = "YOUR_PROVIDER_KEY"
```

For optional external SWE-bench style runs, keep provider configuration outside
the repository and point scripts at that private file:

```powershell
$env:TAUGUARDIAN_SWEBENCH_CONFIG = "C:\path\to\private\swebench-config.yaml"
```

Example shape for a private config file:

```yaml
model:
  provider: "litellm"
  model_name: "provider/model-name"
  api_key: "${TAUGUARDIAN_PROVIDER_KEY}"
```

This is a placeholder example only. Do not commit the private config file.
