# Troubleshooting Guide

Common issues and solutions when setting up and running the Azure Security Scanner.

## Table of Contents

1. [Authentication Issues](#authentication-issues)
1. [Key Vault Access Problems](#key-vault-access-problems)
1. [Permission Errors](#permission-errors)
1. [Scanner Execution Issues](#scanner-execution-issues)
1. [Network Connectivity](#network-connectivity)
1. [Python and Dependencies](#python-and-dependencies)
1. [Azure CLI Issues](#azure-cli-issues)
1. [Report Generation Problems](#report-generation-problems)
1. [Performance Issues](#performance-issues)
1. [Known Limitations](#known-limitations)

## Authentication Issues

### Issue: “DefaultAzureCredential failed to retrieve a token”

**Symptoms:**

```
DefaultAzureCredential failed to retrieve a token from the included credentials.
Attempted credentials: EnvironmentCredential, ManagedIdentityCredential, SharedTokenCacheCredential, AzureCliCredential
```

**Causes:**

- Not logged into Azure CLI
- Credentials not set in environment variables
- No Managed Identity on the resource
- Key Vault name not configured

**Solutions:**

1. **Login to Azure CLI:**
   
   ```bash
   az login
   az account show
   ```
1. **Set environment variables explicitly:**
   
   ```bash
   export AZURE_CLIENT_ID="your-client-id"
   export AZURE_CLIENT_SECRET="your-client-secret"
   export AZURE_TENANT_ID="your-tenant-id"
   export AZURE_SUBSCRIPTION_ID="your-subscription-id"
   ```
1. **Use Key Vault authentication:**
   
   ```bash
   export AZURE_KEY_VAULT_NAME="your-keyvault-name"
   python azure_security_scanner.py
   ```
1. **Verify .env file is present and correct:**
   
   ```bash
   cat .env
   # Should contain:
   # AZURE_SUBSCRIPTION_ID=...
   # AZURE_KEY_VAULT_NAME=...
   ```

### Issue: “Authentication failed: Client assertion is not within its valid time range”

**Symptoms:**

```
Client assertion is not within its valid time range. Current time: 2025-10-28, 
assertion valid from 2025-10-27 to 2025-10-28
```

**Cause:**

- System clock is out of sync

**Solution:**

```bash
# Linux/macOS - sync system time
sudo ntpdate -s time.nist.gov

# Windows - sync time in Settings
# Settings > Time & Language > Date & Time > Sync now
```

### Issue: “Service Principal authentication failed”

**Symptoms:**

```
AADSTS7000215: Invalid client secret provided
```

**Cause:**

- Incorrect client secret
- Client secret expired
- Wrong tenant ID

**Solution:**

1. **Verify credentials:**
   
   ```bash
   # Test Service Principal login
   az login --service-principal \
     -u YOUR_CLIENT_ID \
     -p YOUR_CLIENT_SECRET \
     --tenant YOUR_TENANT_ID
   ```
1. **Reset Service Principal credentials:**
   
   ```bash
   az ad sp credential reset --id YOUR_CLIENT_ID
   # Update the secret in Key Vault
   az keyvault secret set \
     --vault-name YOUR_VAULT \
     --name azure-client-secret \
     --value NEW_SECRET
   ```
1. **Verify tenant ID:**
   
   ```bash
   az account show --query tenantId -o tsv
   ```

## Key Vault Access Problems

### Issue: “Operation returned an invalid status code ‘Forbidden’”

**Symptoms:**

```
azure.core.exceptions.HttpResponseError: Operation returned an invalid status 
code 'Forbidden'
```

**Cause:**

- Service Principal doesn’t have permission to access Key Vault
- RBAC not properly configured
- Access policy not set (for non-RBAC vaults)

**Solutions:**

1. **For RBAC-enabled Key Vaults:**
   
   ```bash
   # Get Service Principal app ID
   SP_APP_ID=$(az ad sp list --display-name "AzureSecurityScanner" --query "[0].appId" -o tsv)
   
   # Get Key Vault ID
   VAULT_ID=$(az keyvault show --name YOUR_VAULT --query id -o tsv)
   
   # Assign Key Vault Secrets User role
   az role assignment create \
     --assignee $SP_APP_ID \
     --role "Key Vault Secrets User" \
     --scope $VAULT_ID
   
   # Wait for RBAC propagation (can take up to 5 minutes)
   sleep 300
   ```
1. **For Access Policy-based Key Vaults:**
   
   ```bash
   az keyvault set-policy \
     --name YOUR_VAULT \
     --spn $SP_APP_ID \
     --secret-permissions get list
   ```
1. **Verify access:**
   
   ```bash
   # Test secret retrieval
   az keyvault secret show \
     --vault-name YOUR_VAULT \
     --name azure-client-id
   ```

### Issue: “Key Vault not found”

**Symptoms:**

```
ResourceNotFoundError: The vault with name 'my-vault' was not found
```

**Cause:**

- Key Vault name is incorrect
- Key Vault doesn’t exist
- Key Vault is in a different subscription

**Solutions:**

1. **List available Key Vaults:**
   
   ```bash
   az keyvault list --output table
   ```
1. **Check Key Vault name in .env:**
   
   ```bash
   grep AZURE_KEY_VAULT_NAME .env
   ```
1. **Verify subscription:**
   
   ```bash
   az account show
   # Make sure you're in the correct subscription
   az account set --subscription "correct-subscription"
   ```

### Issue: “Secret not found in Key Vault”

**Symptoms:**

```
ResourceNotFoundError: Secret not found: azure-client-id
```

**Cause:**

- Secret name is incorrect
- Secret hasn’t been created
- Secret was deleted and is in soft-delete state

**Solutions:**

1. **List secrets in Key Vault:**
   
   ```bash
   az keyvault secret list --vault-name YOUR_VAULT --output table
   ```
1. **Check for soft-deleted secrets:**
   
   ```bash
   az keyvault secret list-deleted --vault-name YOUR_VAULT --output table
   ```
1. **Recover deleted secret:**
   
   ```bash
   az keyvault secret recover \
     --vault-name YOUR_VAULT \
     --name azure-client-id
   ```
1. **Create missing secret:**
   
   ```bash
   az keyvault secret set \
     --vault-name YOUR_VAULT \
     --name azure-client-id \
     --value YOUR_CLIENT_ID
   ```

## Permission Errors

### Issue: “AuthorizationFailed: does not have authorization to perform action”

**Symptoms:**

```
AuthorizationFailed: The client 'abc-123' with object id 'xyz-789' does not 
have authorization to perform action 'Microsoft.Storage/storageAccounts/read'
```

**Cause:**

- Service Principal doesn’t have required RBAC roles
- Role assignment scope is incorrect

**Solutions:**

1. **Check current role assignments:**
   
   ```bash
   SP_OBJECT_ID=$(az ad sp list --display-name "AzureSecurityScanner" --query "[0].id" -o tsv)
   az role assignment list --assignee $SP_OBJECT_ID --output table
   ```
1. **Assign Reader role at subscription level:**
   
   ```bash
   SUBSCRIPTION_ID=$(az account show --query id -o tsv)
   az role assignment create \
     --assignee $SP_OBJECT_ID \
     --role "Reader" \
     --scope "/subscriptions/$SUBSCRIPTION_ID"
   ```
1. **Assign Security Reader role:**
   
   ```bash
   az role assignment create \
     --assignee $SP_OBJECT_ID \
     --role "Security Reader" \
     --scope "/subscriptions/$SUBSCRIPTION_ID"
   ```
1. **Wait for permission propagation:**
   
   ```bash
   # Permissions can take up to 5 minutes to propagate
   sleep 300
   ```

### Issue: “Insufficient privileges to complete the operation”

**Symptoms:**

```
GraphError: Insufficient privileges to complete the operation
```

**Cause:**

- Service Principal doesn’t have permissions to read Azure AD objects
- Trying to perform operations requiring higher privileges

**Solution:**

This is expected behavior. The scanner only needs to read resources, not Azure AD objects. The scanner will continue to work for other security checks.

If you need Azure AD permissions:

```bash
# Requires Global Administrator or Privileged Role Administrator
az ad sp update --id $SP_OBJECT_ID --set 'appRoleAssignments'
```

## Scanner Execution Issues

### Issue: “No module named ‘azure’”

**Symptoms:**

```
ModuleNotFoundError: No module named 'azure'
```

**Cause:**

- Python dependencies not installed
- Wrong Python environment activated

**Solutions:**

1. **Install dependencies:**
   
   ```bash
   pip install -r requirements.txt
   ```
1. **Verify installation:**
   
   ```bash
   pip list | grep azure
   ```
1. **Use virtual environment:**
   
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```

### Issue: “Scanner finds no resources”

**Symptoms:**

```
Found 0 storage account(s)
Found 0 Network Security Group(s)
```

**Causes:**

- No resources exist in the subscription
- Scanning the wrong subscription
- Permission issues (silent failures)

**Solutions:**

1. **Verify subscription has resources:**
   
   ```bash
   az resource list --output table
   ```
1. **Check current subscription:**
   
   ```bash
   az account show
   ```
1. **Run with verbose logging:**
   
   ```bash
   python azure_security_scanner.py --verbose
   ```
1. **Test API access manually:**
   
   ```bash
   az storage account list --output table
   az network nsg list --output table
   ```

### Issue: “Scanner times out”

**Symptoms:**

```
OperationNotComplete: The operation did not complete within the allowed time.
```

**Cause:**

- Too many resources to scan
- Network latency
- Azure API throttling

**Solutions:**

1. **Scan specific resource group:**
   
   ```bash
   python azure_security_scanner.py --resource-group "my-rg"
   ```
1. **Increase timeout (modify scanner code):**
   
   ```python
   # In azure_security_scanner.py
   from azure.core.pipeline.policies import RetryPolicy
   
   retry_policy = RetryPolicy(
       retry_total=3,
       retry_backoff_factor=2
   )
   ```
1. **Scan fewer resource types:**
   
   ```python
   # Comment out scans you don't need
   # total_scanned += self.scan_virtual_machines()
   ```

## Network Connectivity

### Issue: “Connection timeout” or “Name resolution failed”

**Symptoms:**

```
requests.exceptions.ConnectionError: Failed to establish a new connection
```

**Cause:**

- No internet connectivity
- Firewall blocking Azure endpoints
- Proxy configuration needed

**Solutions:**

1. **Test Azure connectivity:**
   
   ```bash
   curl -I https://management.azure.com
   ping login.microsoftonline.com
   ```
1. **Configure proxy (if needed):**
   
   ```bash
   export HTTP_PROXY=http://proxy.company.com:8080
   export HTTPS_PROXY=http://proxy.company.com:8080
   ```
1. **Check DNS resolution:**
   
   ```bash
   nslookup management.azure.com
   ```
1. **Verify certificate trust:**
   
   ```bash
   # Update CA certificates
   # Ubuntu/Debian
   sudo update-ca-certificates
   
   # RHEL/CentOS
   sudo update-ca-trust
   ```

### Issue: “SSL Certificate verification failed”

**Symptoms:**

```
ssl.SSLCertVerificationError: certificate verify failed: unable to get local issuer certificate
```

**Cause:**

- Corporate SSL inspection
- Outdated certificate store
- Self-signed certificates in chain

**Solutions:**

1. **Update certificate store:**
   
   ```bash
   pip install --upgrade certifi
   ```
1. **Set custom CA bundle (temporary, not recommended for production):**
   
   ```bash
   export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt
   ```
1. **For development only (INSECURE):**
   
   ```python
   # Add to scanner code (NOT for production!)
   import urllib3
   urllib3.disable_warnings()
   ```

## Python and Dependencies

### Issue: “ImportError: cannot import name ‘SecretClient’”

**Symptoms:**

```
ImportError: cannot import name 'SecretClient' from 'azure.keyvault.secrets'
```

**Cause:**

- Old version of Azure SDK installed
- Package namespace conflicts

**Solutions:**

1. **Uninstall old packages:**
   
   ```bash
   pip uninstall azure-keyvault
   pip uninstall azure-keyvault-secrets
   ```
1. **Install correct package:**
   
   ```bash
   pip install azure-keyvault-secrets>=4.7.0
   ```
1. **Clear pip cache:**
   
   ```bash
   pip cache purge
   pip install -r requirements.txt --force-reinstall
   ```

### Issue: “SyntaxError: invalid syntax”

**Symptoms:**

```
SyntaxError: invalid syntax (f-strings require Python 3.6+)
```

**Cause:**

- Python version is too old (< 3.8)

**Solution:**

1. **Check Python version:**
   
   ```bash
   python --version
   ```
1. **Upgrade Python or use specific version:**
   
   ```bash
   # Use python3 explicitly
   python3 azure_security_scanner.py
   
   # Or install Python 3.10+
   # Ubuntu/Debian
   sudo apt install python3.10
   
   # macOS
   brew install python@3.10
   ```

## Azure CLI Issues

### Issue: “az: command not found”

**Cause:**

- Azure CLI not installed
- Not in PATH

**Solutions:**

1. **Install Azure CLI:**
   
   ```bash
   # macOS
   brew install azure-cli
   
   # Windows
   winget install Microsoft.AzureCLI
   
   # Linux
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   ```
1. **Add to PATH:**
   
   ```bash
   export PATH=$PATH:/usr/local/bin
   ```

### Issue: “az: The token is expired”

**Symptoms:**

```
Token has expired, please run 'az login' to setup account.
```

**Solution:**

```bash
az login
az account show
```

### Issue: “az: Please run ‘az login’ to setup account”

**Cause:**

- Not authenticated with Azure CLI

**Solution:**

```bash
az login

# For Service Principal
az login --service-principal \
  -u YOUR_CLIENT_ID \
  -p YOUR_CLIENT_SECRET \
  --tenant YOUR_TENANT_ID

# Verify login
az account show
```

## Report Generation Problems

### Issue: “Permission denied: reports/”

**Symptoms:**

```
PermissionError: [Errno 13] Permission denied: 'reports/security_report_20251028.json'
```

**Cause:**

- No write permissions on reports directory
- Reports directory doesn’t exist

**Solutions:**

1. **Create reports directory:**
   
   ```bash
   mkdir -p reports
   chmod 755 reports
   ```
1. **Run with appropriate permissions:**
   
   ```bash
   # Linux/macOS
   sudo python azure_security_scanner.py
   
   # Or change ownership
   sudo chown $USER:$USER reports/
   ```

### Issue: “UnicodeEncodeError in report generation”

**Symptoms:**

```
UnicodeEncodeError: 'ascii' codec can't encode character
```

**Cause:**

- Resource names contain special characters
- Default encoding is not UTF-8

**Solution:**

Set UTF-8 encoding:

```bash
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Or modify scanner code
import sys
sys.stdout.reconfigure(encoding='utf-8')
```

## Performance Issues

### Issue: “Scanner is very slow”

**Causes:**

- Large number of resources
- Network latency
- Azure API throttling

**Solutions:**

1. **Scan specific resource groups:**
   
   ```bash
   python azure_security_scanner.py --resource-group "prod-rg"
   ```
1. **Use parallel scanning (modify code):**
   
   ```python
   from concurrent.futures import ThreadPoolExecutor
   
   with ThreadPoolExecutor(max_workers=5) as executor:
       futures = [
           executor.submit(self.scan_storage_accounts),
           executor.submit(self.scan_network_security_groups),
           # etc.
       ]
   ```
1. **Implement caching:**
   
   ```python
   from functools import lru_cache
   
   @lru_cache(maxsize=100)
   def get_resource(resource_id):
       # Cached resource fetching
       pass
   ```

### Issue: “Rate limiting errors”

**Symptoms:**

```
TooManyRequests: Rate limit exceeded. Retry after 60 seconds.
```

**Cause:**

- Too many API calls in short time
- Azure throttling limits reached

**Solution:**

Add retry logic (already implemented in SDK, but can adjust):

```python
from azure.core.pipeline.policies import RetryPolicy
from azure.core.pipeline.transport import RequestsTransport

transport = RequestsTransport(
    connection_timeout=300,
    read_timeout=300
)

# Clients will automatically retry on throttling
```

## Known Limitations

### Feature Limitations

1. **Azure AD Permissions**
- Scanner cannot read Azure AD objects without additional permissions
- Service Principal creation requires elevated Azure AD roles
1. **Subscription Scope**
- Scanner works on single subscription per run
- Management group scanning not supported
1. **Resource Type Support**
- Only covers Storage, Network, Compute, and Key Vault
- Does not scan App Services, Functions, Databases (yet)
1. **Compliance Frameworks**
- Implements common best practices
- Does not validate against specific compliance frameworks (HIPAA, PCI-DSS)

### Azure Limitations

1. **RBAC Propagation**
- Role assignments can take up to 5 minutes to take effect
- Always wait after creating new role assignments
1. **API Throttling**
- Azure enforces rate limits on API calls
- Scanner respects these limits automatically
1. **Resource Limits**
- Some subscriptions have limits on resources
- Very large subscriptions may require pagination

## Getting Additional Help

### Enable Debug Logging

```bash
# Maximum verbosity
python azure_security_scanner.py --verbose

# Check log file
cat azure_security_scanner.log
```

### Collect Diagnostic Information

```bash
# System info
python --version
az --version

# Azure info
az account show
az role assignment list --assignee $SP_ID

# Package versions
pip list | grep azure

# Network test
curl -I https://management.azure.com
```

### Where to Get Help

1. **GitHub Issues**: [Report issues or ask questions](https://github.com/yourusername/Learning-Azure-Security/issues)
1. **Azure Documentation**: [Official Azure docs](https://docs.microsoft.com/azure/)
1. **Azure Support**: For Azure-specific issues, contact Azure support
1. **Stack Overflow**: Tag questions with `azure`, `azure-security`, `python`

### Common Error Code Reference

|Error Code|Meaning            |Solution                             |
|----------|-------------------|-------------------------------------|
|401       |Unauthorized       |Check authentication credentials     |
|403       |Forbidden          |Verify RBAC permissions              |
|404       |Not Found          |Check resource names and subscription|
|429       |Too Many Requests  |Wait and retry (automatic)           |
|503       |Service Unavailable|Azure service issue, retry later     |

## Troubleshooting Checklist

Before reporting an issue, verify:

- [ ] Python version is 3.8 or higher
- [ ] Azure CLI is installed and logged in
- [ ] All dependencies installed: `pip install -r requirements.txt`
- [ ] .env file is configured correctly
- [ ] Service Principal has Reader role
- [ ] Key Vault access is configured (if using Key Vault)
- [ ] Subscription ID is correct
- [ ] Network connectivity to Azure
- [ ] Logs checked: `cat azure_security_scanner.log`

## Reporting Bugs

When reporting issues, include:

1. **Error message** (full stack trace)
1. **Command used** (with sensitive data redacted)
1. **Environment**:
- OS and version
- Python version
- Azure CLI version
- Package versions: `pip freeze`
1. **Log file** (`azure_security_scanner.log`)
1. **Steps to reproduce**

Example bug report template:

```markdown
## Bug Description
[Clear description of the issue]

## Steps to Reproduce
1. ...
2. ...
3. ...

## Expected Behavior
[What should happen]

## Actual Behavior
[What actually happens]

## Environment
- OS: Ubuntu 22.04
- Python: 3.10.5
- Azure CLI: 2.53.0
- Scanner version: [commit hash]

## Logs
```

[Paste relevant log excerpts]

```
## Additional Context
[Any other relevant information]
```

-----

Still having issues? Open a GitHub issue with the information above!
