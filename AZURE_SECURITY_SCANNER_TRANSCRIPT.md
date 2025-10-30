## Azure Security Scanner – Plain-English Walkthrough (for Podcast)

### What this tool is
This script looks at your Azure subscription and checks a few common security settings. It signs in, reads secrets (if you keep them in Key Vault), scans some resource types, and then produces a simple report.

### Before it runs
- It tries to load settings from a local `.env` file (if present):
  - `AZURE_SUBSCRIPTION_ID`
  - `AZURE_KEY_VAULT_NAME` (optional)
- You can also pass these on the command line or export them as environment variables.

### Step 1: Start-up and configuration
When you start the program, it prints that it’s initializing. It records which subscription you’re targeting and sets up logging so that messages appear on screen and in a log file.

### Step 2: Authentication
The scanner needs an Azure token to read resources. It tries one of two paths:
1) If a Key Vault name is provided:
   - It connects to the Key Vault.
   - It reads three secrets: `azure-client-id`, `azure-client-secret`, and `azure-tenant-id`.
   - Using those, it creates a Service Principal credential to talk to Azure.
2) If no Key Vault name is provided:
   - It uses “DefaultAzureCredential,” which can sign in with your Azure CLI login, Managed Identity, or other local methods.

As a quick test, it lists resource groups. If that works, we’re authenticated.

### Step 3: The scans
The scanner runs a few focused checks. Think of them as quick health checks, not a full audit.

- Storage Accounts
  - Looks for public access exposure.
  - Confirms HTTPS-only is enforced.
  - Checks encryption-at-rest settings.
  - Verifies minimum TLS version (aims for TLS 1.2).

- Network Security Groups (NSGs)
  - Searches for rules that allow the whole internet (0.0.0.0/0).
  - Flags when risky ports (like 22 or 3389) might be open.

- Key Vaults
  - Ensures “soft delete” is enabled (safety net against accidental deletion).
  - Encourages enabling “purge protection” in production.
  - Checks whether network access is restricted or wide open.

- Virtual Machines
  - Notes whether boot diagnostics is enabled (useful for troubleshooting).
  - Notes whether a Managed Identity is configured (helps avoid stored secrets).

For each potential issue, it adds a finding with a short recommendation on what to improve.

### Step 4: Report generation
At the end, the scanner builds a summary and writes a report into the `reports/` folder.
- JSON report by default, HTML if you ask for it.
- The report includes all findings and a quick summary of counts by severity.

### Step 5: Exit code and what it means
- If there are any HIGH severity findings, the tool exits with a non-zero code (good for CI pipelines to fail fast).
- If no HIGH findings are present, it exits with success.

### How to run it (typical)
1) Make sure you’re logged in with Azure CLI, or have the right secrets in Key Vault.
2) Create a `.env` file with:
   - `AZURE_SUBSCRIPTION_ID=...`
   - `AZURE_KEY_VAULT_NAME=...` (optional)
3) Run:
```bash
python azure_security_scanner.py --output json
```
Or specify everything explicitly:
```bash
python azure_security_scanner.py \
  --subscription-id "<your-subscription-id>" \
  --key-vault "<your-key-vault-name>" \
  --output html
```

### What this is (and isn’t)
- It is a quick, opinionated scan for common misconfigurations.
- It isn’t a replacement for full security benchmarks or a complete compliance audit.

### Privacy and safety
- If you used Key Vault, your credentials are read at runtime from secrets you control.
- Reports are saved locally in the `reports/` folder; handle them as sensitive output if they contain details about your environment.

### One-sentence summary
“The script signs in, reads optional secrets from Key Vault, checks a handful of high-impact security settings across your Azure resources, and writes a simple report you can act on.”


