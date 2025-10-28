# Azure Setup Guide

This guide provides detailed instructions for setting up Azure resources required for the Security Scanner.

## Table of Contents

1. [Prerequisites](#prerequisites)
1. [Quick Setup (Automated)](#quick-setup-automated)
1. [Manual Setup](#manual-setup)
1. [Azure Resource Overview](#azure-resource-overview)
1. [Authentication Methods](#authentication-methods)
1. [Permissions and Roles](#permissions-and-roles)
1. [Verification Steps](#verification-steps)

## Prerequisites

### Required Tools

- **Azure CLI** (version 2.50.0 or later)
  
  ```bash
  # Install on macOS
  brew install azure-cli
  
  # Install on Windows
  winget install Microsoft.AzureCLI
  
  # Install on Linux
  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
  ```
- **Python 3.8+**
  
  ```bash
  python --version  # Should be 3.8 or higher
  ```
- **jq** (for JSON parsing in setup script)
  
  ```bash
  # macOS
  brew install jq
  
  # Ubuntu/Debian
  sudo apt-get install jq
  
  # Windows
  winget install jqlang.jq
  ```

### Required Permissions

You need the following permissions in your Azure subscription:

- Create Service Principals (Application Administrator or Global Administrator)
- Create Resource Groups
- Create Key Vaults
- Assign RBAC roles at subscription level
- Create role assignments

## Quick Setup (Automated)

The fastest way to get started:

```bash
# Make the script executable
chmod +x quick-setup.sh

# Run the automated setup
./quick-setup.sh
```

The script will:

1. ✅ Verify Azure CLI installation and login
1. ✅ Create a resource group
1. ✅ Create a Service Principal with Reader permissions
1. ✅ Create an Azure Key Vault
1. ✅ Store credentials securely in Key Vault
1. ✅ Configure RBAC permissions
1. ✅ Generate .env configuration file

## Manual Setup

If you prefer manual setup or need more control:

### Step 1: Azure Login

```bash
# Login to Azure
az login

# List available subscriptions
az account list --output table

# Set the subscription you want to use
az account set --subscription "Your-Subscription-Name"

# Verify current subscription
az account show
```

### Step 2: Create Resource Group

```bash
# Define variables
RESOURCE_GROUP="security-scanner-rg"
LOCATION="eastus"

# Create resource group
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION

# Verify creation
az group show --name $RESOURCE_GROUP
```

### Step 3: Create Service Principal

```bash
# Get your subscription ID
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

# Create Service Principal with Reader role
az ad sp create-for-rbac \
  --name "AzureSecurityScanner" \
  --role "Reader" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --query '{clientId: appId, clientSecret: password, tenantId: tenant}'
```

**IMPORTANT**: Save this output immediately! You cannot retrieve the secret later.

```json
{
  "clientId": "12345678-1234-1234-1234-123456789abc",
  "clientSecret": "your-secret-here",
  "tenantId": "87654321-4321-4321-4321-cba987654321"
}
```

### Step 4: Assign Additional Roles

```bash
# Get Service Principal Object ID
SP_OBJECT_ID=$(az ad sp list --display-name "AzureSecurityScanner" --query "[0].id" -o tsv)
SP_APP_ID=$(az ad sp list --display-name "AzureSecurityScanner" --query "[0].appId" -o tsv)

# Assign Security Reader role (for security assessments)
az role assignment create \
  --assignee $SP_OBJECT_ID \
  --role "Security Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"

# Assign Key Vault Reader role (for Key Vault scanning)
az role assignment create \
  --assignee $SP_OBJECT_ID \
  --role "Key Vault Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"

# Verify role assignments
az role assignment list --assignee $SP_APP_ID --output table
```

### Step 5: Create Key Vault

```bash
# Choose a globally unique name
KEY_VAULT_NAME="security-scanner-kv-$USER"

# Create Key Vault with RBAC authorization
az keyvault create \
  --name $KEY_VAULT_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --enable-rbac-authorization true \
  --enable-soft-delete true \
  --enable-purge-protection true

# Get Key Vault ID
KEY_VAULT_ID=$(az keyvault show --name $KEY_VAULT_NAME --query id -o tsv)
```

### Step 6: Configure Key Vault Access

```bash
# Get your user ID
USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)

# Assign yourself Key Vault Secrets Officer role
az role assignment create \
  --assignee $USER_OBJECT_ID \
  --role "Key Vault Secrets Officer" \
  --scope $KEY_VAULT_ID

# Grant Service Principal Key Vault Secrets User role
az role assignment create \
  --assignee $SP_APP_ID \
  --role "Key Vault Secrets User" \
  --scope $KEY_VAULT_ID

# Wait for RBAC propagation
sleep 10
```

### Step 7: Store Credentials in Key Vault

```bash
# Store Service Principal credentials
az keyvault secret set \
  --vault-name $KEY_VAULT_NAME \
  --name "azure-client-id" \
  --value "YOUR_CLIENT_ID_HERE"

az keyvault secret set \
  --vault-name $KEY_VAULT_NAME \
  --name "azure-client-secret" \
  --value "YOUR_CLIENT_SECRET_HERE"

az keyvault secret set \
  --vault-name $KEY_VAULT_NAME \
  --name "azure-tenant-id" \
  --value "YOUR_TENANT_ID_HERE"

# Verify secrets are stored
az keyvault secret list --vault-name $KEY_VAULT_NAME --output table
```

### Step 8: Create Environment Configuration

```bash
# Create .env file
cat > .env << EOF
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_KEY_VAULT_NAME=$KEY_VAULT_NAME
OUTPUT_FORMAT=json
VERBOSE=false
EOF

echo "✓ Configuration saved to .env"
```

## Azure Resource Overview

### Resources Created

1. **Resource Group** (`security-scanner-rg`)
- Container for all scanner resources
- Simplifies cleanup and management
- Cost tracking and organization
1. **Service Principal** (`AzureSecurityScanner`)
- Application identity for authentication
- Assigned Reader role for resource access
- Security Reader role for security data
- Key Vault Reader for vault metadata
1. **Key Vault** (`security-scanner-kv-*`)
- Secure storage for credentials
- RBAC-based access control
- Soft delete and purge protection enabled
- Audit logging available

### Resource Costs

- **Resource Group**: Free
- **Service Principal**: Free
- **Key Vault**: ~$0.03 per 10,000 operations
- **Key Vault Secrets**: $0.03 per secret per month

**Estimated monthly cost**: < $1 USD

## Authentication Methods

The scanner supports multiple authentication methods:

### 1. Key Vault Authentication (Recommended for Production)

```bash
# Set environment variable
export AZURE_KEY_VAULT_NAME="your-keyvault-name"

# Run scanner
python azure_security_scanner.py
```

**Pros**:

- Secure credential storage
- Centralized secret management
- Audit logging
- Credential rotation support

**Cons**:

- Requires initial setup
- Additional Azure resource

### 2. DefaultAzureCredential (Good for Development)

```bash
# Login with Azure CLI
az login

# Don't set AZURE_KEY_VAULT_NAME
# Run scanner
python azure_security_scanner.py
```

**Credential Chain**:

1. Environment variables (AZURE_CLIENT_ID, etc.)
1. Managed Identity (if running on Azure)
1. Azure CLI credentials
1. Azure PowerShell credentials

**Pros**:

- No Key Vault setup needed
- Works with Azure CLI login
- Supports Managed Identity

**Cons**:

- Less suitable for production
- Credentials may be stored locally

### 3. Managed Identity (Best for Azure VMs)

If running on an Azure VM or App Service:

```bash
# Enable system-assigned managed identity
az vm identity assign \
  --name "your-vm-name" \
  --resource-group "your-rg"

# Get the managed identity principal ID
PRINCIPAL_ID=$(az vm show \
  --name "your-vm-name" \
  --resource-group "your-rg" \
  --query identity.principalId -o tsv)

# Assign Reader role
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"

# Assign Security Reader role
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Security Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

**Pros**:

- No credential management
- Automatic credential rotation
- Best security practice for Azure resources

**Cons**:

- Only works on Azure compute resources
- Cannot test locally

## Permissions and Roles

### Minimum Required Roles

For the Service Principal or Managed Identity:

|Role                      |Purpose                     |Scope       |
|--------------------------|----------------------------|------------|
|**Reader**                |Read resource configurations|Subscription|
|**Security Reader**       |Access security assessments |Subscription|
|**Key Vault Reader**      |Read Key Vault metadata     |Subscription|
|**Key Vault Secrets User**|Read secrets from Key Vault |Key Vault   |

### Creating Custom Role (Optional)

For least privilege access:

```bash
# Create custom role definition
cat > scanner-role.json << 'EOF'
{
  "Name": "Security Scanner Reader",
  "Description": "Read-only access for security scanning",
  "Actions": [
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.Security/*/read"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/YOUR_SUBSCRIPTION_ID"
  ]
}
EOF

# Create the role
az role definition create --role-definition scanner-role.json

# Assign to Service Principal
az role assignment create \
  --assignee $SP_APP_ID \
  --role "Security Scanner Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

## Verification Steps

### 1. Verify Azure CLI Access

```bash
# Check current account
az account show

# Expected output: Your subscription details
```

### 2. Verify Service Principal

```bash
# List Service Principals
az ad sp list --display-name "AzureSecurityScanner" --output table

# Test Service Principal login
az login --service-principal \
  -u YOUR_CLIENT_ID \
  -p YOUR_CLIENT_SECRET \
  --tenant YOUR_TENANT_ID

# List resources (should succeed)
az resource list --output table
```

### 3. Verify Key Vault Access

```bash
# List Key Vault secrets
az keyvault secret list \
  --vault-name $KEY_VAULT_NAME \
  --output table

# Retrieve a secret
az keyvault secret show \
  --vault-name $KEY_VAULT_NAME \
  --name "azure-client-id"
```

### 4. Verify Python Environment

```bash
# Install dependencies
pip install -r requirements.txt

# Test import
python -c "from azure.identity import DefaultAzureCredential; print('✓ Azure SDK installed')"
```

### 5. Test the Scanner

```bash
# Run a quick test
python azure_security_scanner.py --verbose

# Check for successful authentication
# Expected: "[INFO] Authentication successful!"
```

## Advanced Configuration

### Multi-Subscription Scanning

To scan multiple subscriptions:

```bash
# Create Service Principal with access to multiple subscriptions
az ad sp create-for-rbac \
  --name "AzureSecurityScannerMulti" \
  --role "Reader" \
  --scopes \
    "/subscriptions/subscription-id-1" \
    "/subscriptions/subscription-id-2"

# Run scanner for each subscription
python azure_security_scanner.py --subscription-id "subscription-1"
python azure_security_scanner.py --subscription-id "subscription-2"
```

### Using Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: AzureCLI@2
  inputs:
    azureSubscription: 'your-service-connection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      pip install -r requirements.txt
      python azure_security_scanner.py --output html
      
- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: 'reports'
    ArtifactName: 'security-reports'
```

### Using GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Azure Security Scan

on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run Security Scan
        run: python azure_security_scanner.py --output html
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: reports/
```

## Cleanup

To remove all created resources:

```bash
# Delete Resource Group (deletes all resources)
az group delete --name security-scanner-rg --yes --no-wait

# Delete Service Principal
az ad sp delete --id $(az ad sp list --display-name "AzureSecurityScanner" --query "[0].id" -o tsv)

# Delete local files
rm .env
rm -rf reports/
```

## Next Steps

1. Review [Security Best Practices](SECURITY_BEST_PRACTICES.md)
1. Check [Troubleshooting Guide](TROUBLESHOOTING.md) if you encounter issues
1. Run your first scan: `python azure_security_scanner.py`
1. Schedule regular scans using cron or Azure Automation

## Additional Resources

- [Azure CLI Documentation](https://docs.microsoft.com/cli/azure/)
- [Service Principal Best Practices](https://docs.microsoft.com/azure/active-directory/develop/howto-create-service-principal-portal)
- [Azure Key Vault Documentation](https://docs.microsoft.com/azure/key-vault/)
- [Azure RBAC Documentation](https://docs.microsoft.com/azure/role-based-access-control/)
